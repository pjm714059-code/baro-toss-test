var express = require("express");
var got = require("got");
var { resolve } = require("path");
var crypto = require("crypto");

var app = express();

app.use(express.static(__dirname + "/public"));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/**
 * ✅ 실사용 전제 설정
 * - TOSS_SECRET_KEY: 토스 시크릿 키 (절대 공개 금지)
 * - ORDER_SIGNING_SECRET: 주문 서명용 비밀키 (권장: Render 환경변수로 반드시 설정)
 *
 * ⚠️ ORDER_SIGNING_SECRET이 없으면 TOSS_SECRET_KEY로 대체하지만,
 *    운영에선 분리하는 게 가장 안전함.
 */
var secretKey = process.env.TOSS_SECRET_KEY || "test_gsk_docs_OaPz8L5KdmQXkzRz3y47BMw6";
var signingSecret = process.env.ORDER_SIGNING_SECRET || secretKey;

// ✅ 토스/카드사 심사 대응용 정책값 (너가 정하면 바꿔)
var MAX_AMOUNT = parseInt(process.env.MAX_AMOUNT || "500000", 10); // 건당 최대 결제금액
var ORDER_TTL_MS = parseInt(process.env.ORDER_TTL_MS || String(30 * 60 * 1000), 10); // 30분

// 간단 주문 저장소 (메모리). 운영에선 DB/Redis 권장.
// Render 무료 플랜은 재시작되면 메모리 초기화될 수 있음.
var orders = new Map(); // orderId -> { amount, orderName, createdAt, ip, ua }

function now() {
  return Date.now();
}

function cleanupOrders() {
  var t = now();
  for (var [k, v] of orders.entries()) {
    if (!v || t - v.createdAt > ORDER_TTL_MS) orders.delete(k);
  }
}

function toIntAmount(x) {
  var n = typeof x === "string" ? parseInt(x, 10) : x;
  if (!Number.isFinite(n)) return null;
  if (Math.floor(n) !== n) return null;
  return n;
}

function safeText(s, maxLen) {
  if (typeof s !== "string") return "";
  s = s.trim();
  if (s.length > maxLen) s = s.slice(0, maxLen);
  return s;
}

function hmacSign(payload) {
  return crypto.createHmac("sha256", signingSecret).update(payload).digest("hex").slice(0, 24);
}

/**
 * ✅ 주문 생성 API
 * - 클라가 URL로 amount를 바꾸더라도,
 *   서버가 "이 orderId는 이 amount로 발급됐다"를 보증(서명 + 저장)함.
 */
app.post("/create-order", function (req, res) {
  cleanupOrders();

  var amount = toIntAmount(req.body.amount);
  var orderName = safeText(req.body.orderName || "바로정산", 40);

  if (amount === null || amount <= 0) {
    return res.status(400).json({ ok: false, code: "INVALID_AMOUNT", message: "amount가 올바르지 않습니다." });
  }
  if (amount > MAX_AMOUNT) {
    return res.status(400).json({
      ok: false,
      code: "AMOUNT_EXCEEDS_MAX",
      message: "amount가 최대 결제금액을 초과합니다.",
      maxAmount: MAX_AMOUNT,
    });
  }

  var ts = now();
  var nonce = crypto.randomBytes(8).toString("hex");
  var payload = [amount, orderName, ts, nonce].join("|");
  var sig = hmacSign(payload);

  // orderId는 토스 쪽에서 문자열이면 OK (너무 길지만 않게)
  var orderId = ["BARO", ts, nonce, sig].join("_");

  orders.set(orderId, {
    amount: amount,
    orderName: orderName,
    createdAt: ts,
    ip: req.headers["x-forwarded-for"] || req.socket.remoteAddress || "",
    ua: req.headers["user-agent"] || "",
  });

  return res.json({
    ok: true,
    orderId: orderId,
    amount: amount,
    orderName: orderName,
    maxAmount: MAX_AMOUNT,
    ttlMs: ORDER_TTL_MS,
  });
});

/**
 * ✅ 결제 승인(confirm)
 * - 토스가 successUrl로 넘겨준 paymentKey/orderId/amount를 받아 승인 호출
 * - 여기서 orderId의 서명 + 저장된 원금액과 비교해 "금액 조작" 차단
 */
app.post("/confirm", function (req, res) {
  cleanupOrders();

  var paymentKey = req.body.paymentKey;
  var orderId = req.body.orderId;
  var amount = toIntAmount(req.body.amount);

  if (!paymentKey || !orderId || amount === null) {
    return res.status(400).json({ ok: false, code: "MISSING_FIELDS", message: "paymentKey/orderId/amount가 필요합니다." });
  }

  // orderId 구조: BARO_ts_nonce_sig
  var parts = String(orderId).split("_");
  if (parts.length !== 4 || parts[0] !== "BARO") {
    return res.status(400).json({ ok: false, code: "INVALID_ORDER_ID", message: "orderId 형식이 올바르지 않습니다." });
  }

  var ts = parts[1];
  var nonce = parts[2];
  var sig = parts[3];

  // 저장된 주문 확인
  var saved = orders.get(orderId);
  if (!saved) {
    return res.status(400).json({
      ok: false,
      code: "ORDER_NOT_FOUND",
      message: "주문 정보를 찾을 수 없습니다. (만료/재시작/미발급 가능)",
    });
  }

  // 서명 검증
  var payload = [saved.amount, saved.orderName, ts, nonce].join("|");
  var expectedSig = hmacSign(payload);
  if (sig !== expectedSig) {
    return res.status(400).json({ ok: false, code: "ORDER_TAMPERED", message: "주문 서명 검증 실패(변조 의심)" });
  }

  // amount 검증 (토스 successUrl로 넘어온 amount가 원래 금액과 일치해야 함)
  if (amount !== saved.amount) {
    return res.status(400).json({
      ok: false,
      code: "AMOUNT_MISMATCH",
      message: "결제 금액이 주문 금액과 일치하지 않습니다.",
      expectedAmount: saved.amount,
      receivedAmount: amount,
    });
  }

  // 토스페이먼츠 API 인증 헤더
  var encryptedSecretKey = "Basic " + Buffer.from(secretKey + ":").toString("base64");

  got
    .post("https://api.tosspayments.com/v1/payments/confirm", {
      headers: {
        Authorization: encryptedSecretKey,
        "Content-Type": "application/json",
      },
      json: {
        orderId: orderId,
        amount: amount,
        paymentKey: paymentKey,
      },
      responseType: "json",
    })
    .then(function (response) {
      // 승인 성공 시, 주문 1회성으로 폐기 (재사용 방지)
      orders.delete(orderId);

      res.status(response.statusCode).json({
        ok: true,
        order: { orderId: orderId, amount: amount },
        toss: response.body,
      });
    })
    .catch(function (error) {
      // 승인 실패 시에도 주문은 남겨둘지/지울지 정책 선택
      // 여기선 일단 남겨둠(재시도 가능). 원하면 delete로 바꿔도 됨.
      var status = (error.response && error.response.statusCode) || 500;
      var body = (error.response && error.response.body) || { message: "Unknown error" };

      res.status(status).json({
        ok: false,
        code: "TOSS_CONFIRM_FAILED",
        toss: body,
      });
    });
});

app.get("/", function (req, res) {
  var path = resolve("./public/checkout.html");
  res.sendFile(path);
});

app.get("/success", function (req, res) {
  var path = resolve("./public/success.html");
  res.sendFile(path);
});

app.get("/fail", function (req, res) {
  var path = resolve("./public/fail.html");
  res.sendFile(path);
});

var PORT = process.env.PORT || 4242;
app.listen(PORT, () => console.log(`http://localhost:${PORT} 으로 샘플 앱이 실행되었습니다.`));
