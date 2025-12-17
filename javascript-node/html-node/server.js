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
 */
var secretKey = process.env.TOSS_SECRET_KEY || "test_gsk_docs_OaPz8L5KdmQXkzRz3y47BMw6";
var signingSecret = process.env.ORDER_SIGNING_SECRET || secretKey;

// ✅ 정책값
// 입력 최대 2,000,000원 + 15% = 총 결제최대 2,300,000원
var MAX_AMOUNT = parseInt(process.env.MAX_AMOUNT || "2300000", 10); // ✅ 기본값 수정
var ORDER_TTL_MS = parseInt(process.env.ORDER_TTL_MS || String(30 * 60 * 1000), 10); // 30분

// 간단 주문 저장소 (메모리). 운영에선 DB/Redis 권장.
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

app.post("/confirm", function (req, res) {
  cleanupOrders();

  var paymentKey = req.body.paymentKey;
  var orderId = req.body.orderId;
  var amount = toIntAmount(req.body.amount);

  if (!paymentKey || !orderId || amount === null) {
    return res.status(400).json({ ok: false, code: "MISSING_FIELDS", message: "paymentKey/orderId/amount가 필요합니다." });
  }

  var parts = String(orderId).split("_");
  if (parts.length !== 4 || parts[0] !== "BARO") {
    return res.status(400).json({ ok: false, code: "INVALID_ORDER_ID", message: "orderId 형식이 올바르지 않습니다." });
  }

  var ts = parts[1];
  var nonce = parts[2];
  var sig = parts[3];

  var saved = orders.get(orderId);
  if (!saved) {
    return res.status(400).json({
      ok: false,
      code: "ORDER_NOT_FOUND",
      message: "주문 정보를 찾을 수 없습니다. (만료/재시작/미발급 가능)",
    });
  }

  var payload = [saved.amount, saved.orderName, ts, nonce].join("|");
  var expectedSig = hmacSign(payload);
  if (sig !== expectedSig) {
    return res.status(400).json({ ok: false, code: "ORDER_TAMPERED", message: "주문 서명 검증 실패(변조 의심)" });
  }

  if (amount !== saved.amount) {
    return res.status(400).json({
      ok: false,
      code: "AMOUNT_MISMATCH",
      message: "결제 금액이 주문 금액과 일치하지 않습니다.",
      expectedAmount: saved.amount,
      receivedAmount: amount,
    });
  }

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
      orders.delete(orderId);

      res.status(response.statusCode).json({
        ok: true,
        order: { orderId: orderId, amount: amount },
        toss: response.body,
      });
    })
    .catch(function (error) {
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
