import express from 'express';
import fetch from 'node-fetch';
import cors from 'cors';
import admin from 'firebase-admin';
import dotenv from 'dotenv';
import crypto from 'crypto';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

const LINE_CLIENT_ID = process.env.LINE_CLIENT_ID;
const LINE_CLIENT_SECRET = process.env.LINE_CLIENT_SECRET;
const FIXED_SALT = process.env.SALT;
const FIXED_PEPPER = process.env.PEPPER;

// Firebase Admin 初期化
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, '\n');
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// CORS設定
const allowedOrigins = [
  'https://streak-navi.web.app',
  'https://streak-navi-test.web.app',
  'https://streak-connect.web.app',
  'https://streak-connect-test.web.app',
];

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    },
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type'],
  }),
);

app.use(express.json());

// SALT+PEPPERでハッシュ化
function hashUserIdWithSaltPepper(userId) {
  return crypto
    .createHash('sha256')
    .update(FIXED_SALT + userId + FIXED_PEPPER)
    .digest('hex');
}

// -------------------------------------
// 1. クライアント用: state生成＆LINEログインURL返却
// -------------------------------------
// フロントエンドからは get-line-login-url?redirectAfterLogin=... で呼び出す想定
app.get('/get-line-login-url', async (req, res) => {
  try {
    const origin = req.headers.origin;
    // フロントから渡された「最終的な戻り先（チケット詳細など）」
    const redirectAfterLogin = req.query.redirectAfterLogin || '';

    const state = crypto.randomBytes(16).toString('hex');
    const createdAt = admin.firestore.FieldValue.serverTimestamp();

    // Firestoreにstateと一緒に戻り先URLを保存
    await admin.firestore().collection('oauthStates').doc(state).set({
      createdAt,
      origin,
      redirectAfterLogin,
    });

    // 1. originが許可リストにあるかチェック
    if (!allowedOrigins.includes(origin)) {
      return res.status(400).json({ error: 'Invalid origin' });
    }

    // 2. パスを決定（Navi系ならlogin.html、Connect系ならhome.html）
    // originに /app/login/login.html などを連結するだけ
    const callbackPath = origin.includes('streak-connect')
      ? '/app/home/home.html'
      : '/app/login/login.html';

    const redirectUri = `${origin}${callbackPath}`;

    const scope = 'openid profile';
    // redirect_uri は1回だけ encodeURIComponent する
    const loginUrl = `https://access.line.me/oauth2/v2.1/authorize?response_type=code&client_id=${LINE_CLIENT_ID}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${state}&scope=${scope}`;

    res.json({ loginUrl, state });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to generate login URL' });
  }
});

// -------------------------------------
// 2. LINEコールバック: state検証 + カスタムトークン生成
// -------------------------------------
app.post('/line-login', async (req, res) => {
  const { code, state, redirectUri } = req.body;
  if (!code || !state || !redirectUri) {
    return res
      .status(400)
      .json({ error: 'Missing code, state, or redirectUri' });
  }

  try {
    // 1. state検証（保存していたリダイレクト先を取得）
    const stateDoc = await admin
      .firestore()
      .collection('oauthStates')
      .doc(state)
      .get();

    if (!stateDoc.exists) {
      return res.status(400).json({ error: 'Invalid or expired state' });
    }

    const stateData = stateDoc.data();
    // 検証済みなので削除
    await admin.firestore().collection('oauthStates').doc(state).delete();

    // 2. LINEアクセストークン取得
    const tokenRes = await fetch('https://api.line.me/oauth2/v2.1/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        client_id: LINE_CLIENT_ID,
        client_secret: LINE_CLIENT_SECRET,
      }),
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token || !tokenData.id_token) {
      return res.status(401).json({ error: 'Token exchange failed' });
    }

    // 3. IDトークン検証
    const verifyRes = await fetch('https://api.line.me/oauth2/v2.1/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        id_token: tokenData.id_token,
        client_id: LINE_CLIENT_ID,
      }),
    });
    const verifyData = await verifyRes.json();
    if (verifyData.error) {
      return res.status(401).json({ error: 'Invalid ID token' });
    }

    // 4. プロフィール取得
    const profileRes = await fetch('https://api.line.me/v2/profile', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const profile = await profileRes.json();

    // 5. Firebase カスタムトークン作成
    const hashedUserId = hashUserIdWithSaltPepper(verifyData.sub);
    const customToken = await admin.auth().createCustomToken(hashedUserId);

    // 6. フロントへ返却（保存していた redirectAfterLogin も一緒に返す）
    res.json({
      customToken,
      profile,
      redirectAfterLogin: stateData.redirectAfterLogin,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/', (req, res) =>
  res.send('Unified Auth server (Navi & Connect) is running!'),
);

app.listen(PORT, () =>
  console.log(`Server running at http://localhost:${PORT}`),
);
