import express from 'express';
import fetch from 'node-fetch';
import cors from 'cors';
import admin from 'firebase-admin';
import dotenv from 'dotenv';
import crypto from 'crypto';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// 固定値
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
  'http://localhost:3000/connect',
  'http://localhost:3000/navi',
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

// 補助関数: OriginからNaviかConnectかを判定し、適切なID/Secretを返す
function getLineCredentials(origin) {
  if (origin && origin.includes('streak-navi')) {
    return {
      clientId: process.env.LINE_CLIENT_ID_NAVI,
      clientSecret: process.env.LINE_CLIENT_SECRET_NAVI,
    };
  } else {
    // デフォルト、またはConnect系
    return {
      clientId: process.env.LINE_CLIENT_ID_CONNECT,
      clientSecret: process.env.LINE_CLIENT_SECRET_CONNECT,
    };
  }
}

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
app.get('/get-line-login-url', async (req, res) => {
  try {
    const origin = req.headers.origin;
    const redirectAfterLogin = req.query.redirectAfterLogin || '';

    // Originに基づいて使用するLINEチャネルを選択
    const { clientId } = getLineCredentials(origin);

    const state = crypto.randomBytes(16).toString('hex');
    const createdAt = admin.firestore.FieldValue.serverTimestamp();

    await admin.firestore().collection('oauthStates').doc(state).set({
      createdAt,
      origin,
      redirectAfterLogin,
    });

    // サイトごとに振り分け
    let redirectUri;
    if (origin.includes('localhost:3000/connect')) {
      // ローカル開発時：Next.jsのcallbackルートへ(connect)
      redirectUri = 'http://localhost:3000/connect/callback';
    } else if (origin.includes('localhost:3000/navi')) {
      // ローカル開発時：Next.jsのcallbackルートへ(navi)
      redirectUri = 'http://localhost:3000/navi/callback';
    } else if (origin === 'https://streak-navi.web.app') {
      // NAVI本番環境
      redirectUri = 'https://streak-navi.web.app/app/login/login.html';
    } else if (origin === 'https://streak-navi-test.web.app') {
      // NAVIテスト環境
      redirectUri = 'https://streak-navi-test.web.app/app/login/login.html';
    } else if (origin === 'https://streak-connect.web.app') {
      // CONNECT本番環境
      redirectUri = 'https://streak-connect.web.app/app/home/home.html';
    } else if (origin === 'https://streak-connect-test.web.app') {
      // CONNECTテスト環境
      redirectUri = 'https://streak-connect-test.web.app/app/home/home.html';
    } else {
      return res.status(400).json({ error: 'Invalid origin' });
    }

    const scope = 'openid profile';
    const loginUrl = `https://access.line.me/oauth2/v2.1/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${state}&scope=${scope}`;

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
    // 1. state検証
    const stateDoc = await admin
      .firestore()
      .collection('oauthStates')
      .doc(state)
      .get();
    if (!stateDoc.exists) {
      return res.status(400).json({ error: 'Invalid or expired state' });
    }
    const stateData = stateDoc.data();
    await admin.firestore().collection('oauthStates').doc(state).delete();

    // 2. Originに基づいて適切な認証情報を取得
    const { clientId, clientSecret } = getLineCredentials(stateData.origin);

    // 3. LINEアクセストークン取得
    const tokenRes = await fetch('https://api.line.me/oauth2/v2.1/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        client_id: clientId,
        client_secret: clientSecret,
      }),
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token || !tokenData.id_token) {
      return res.status(401).json({ error: 'Token exchange failed' });
    }

    // 4. IDトークン検証
    const verifyRes = await fetch('https://api.line.me/oauth2/v2.1/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        id_token: tokenData.id_token,
        client_id: clientId,
      }),
    });
    const verifyData = await verifyRes.json();
    if (verifyData.error) {
      return res.status(401).json({ error: 'Invalid ID token' });
    }

    // 5. プロフィール取得
    const profileRes = await fetch('https://api.line.me/v2/profile', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const profile = await profileRes.json();

    // 6. Firebase カスタムトークン作成
    const rawLineUid = verifyData.sub;
    const hashedUserId = hashUserIdWithSaltPepper(rawLineUid);
    const customToken = await admin.auth().createCustomToken(hashedUserId);

    // 7. LINE UID紐付けデータの保存
    const isNavi = stateData.origin.includes('streak-navi');
    const isConnect = stateData.origin.includes('streak-connect');

    const updateData = {
      lineUid: rawLineUid,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    };

    // 該当するフラグだけを true に設定（もう一方は含めないことで既存の値を維持）
    if (isNavi) updateData.isNavi = true;
    if (isConnect) updateData.isConnect = true;

    await admin
      .firestore()
      .collection('lineMessagingIds')
      .doc(hashedUserId)
      .set(updateData, { merge: true });

    // 7. フロントへ返却（保存していた redirectAfterLogin も一緒に返す）
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
  res.send(
    'Unified Auth server (Navi & Connect) with Dual LINE Channels is running!',
  ),
);

app.listen(PORT, () =>
  console.log(`Server running at http://localhost:${PORT}`),
);
