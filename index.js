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

// CORS設定（Vercelの新ドメインを追加）
const allowedOrigins = [
  'https://ssjo.vercel.app',
  'https://ssjo-test.vercel.app',
  'https://streak-navi.web.app',
  'https://streak-navi-test.web.app',
  'https://streak-connect.web.app',
  'https://streak-connect-test.web.app',
  'http://localhost:3000',
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

// 補助関数: OriginまたはパラメータからNaviかConnectかを判定
function getLineCredentials(origin, appType = '') {
  // 明示的なappType指定があるか、URLにnaviが含まれる場合はNavi用チャネルを使用
  if (appType === 'navi' || (origin && origin.includes('navi'))) {
    return {
      clientId: process.env.LINE_CLIENT_ID_NAVI,
      clientSecret: process.env.LINE_CLIENT_SECRET_NAVI,
    };
  } else {
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
    const origin = req.headers.origin || '';
    const appType = req.query.appType || ''; // フロント側から ?appType=navi などで送ることを推奨
    const redirectAfterLogin = req.query.redirectAfterLogin || '';

    const { clientId } = getLineCredentials(origin, appType);

    const state = crypto.randomBytes(16).toString('hex');
    const createdAt = admin.firestore.FieldValue.serverTimestamp();

    await admin.firestore().collection('oauthStates').doc(state).set({
      createdAt,
      origin,
      appType,
      redirectAfterLogin,
    });

    let redirectUri;
    const isNavi = appType === 'navi' || origin.includes('navi');

    // リダイレクト先URLの振り分けロジック
    if (origin.includes('localhost:3000')) {
      redirectUri = isNavi
        ? 'http://localhost:3000/navi/callback'
        : 'http://localhost:3000/connect/callback';
    } else if (origin.includes('ssjo.vercel.app')) {
      redirectUri = isNavi
        ? 'https://ssjo.vercel.app/navi/callback'
        : 'https://ssjo.vercel.app/connect/callback';
    } else if (origin.includes('ssjo-test.vercel.app')) {
      redirectUri = isNavi
        ? 'https://ssjo-test.vercel.app/navi/callback'
        : 'https://ssjo-test.vercel.app/connect/callback';
    } else if (origin.includes('streak-navi')) {
      redirectUri = `${origin}/app/login/login.html`;
    } else {
      // デフォルト（旧Connectなど）
      redirectUri = `${origin}/app/home/home.html`;
    }

    const scope = 'openid profile';
    const loginUrl = `https://access.line.me/oauth2/v2.1/authorize?&bot_prompt=normal&response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${state}&scope=${scope}`;

    res.json({ loginUrl, state, redirectUri }); // デバッグ用にredirectUriも返す
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

    const { clientId, clientSecret } = getLineCredentials(
      stateData.origin,
      stateData.appType,
    );

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

    // TODO検討中 友達追加を必須にするかどうか
    // NAVI：別に全体ラインでよくね？
    // CONNECT：お客さんに強要するのは違くね？
    // // 友だち状態の確認
    // const friendshipRes = await fetch(
    //   'https://api.line.me/friendship/v2.1/status',
    //   {
    //     headers: { Authorization: `Bearer ${tokenData.access_token}` },
    //   },
    // );
    // const friendshipData = await friendshipRes.json();

    // // 友だちではない(friendFlagがfalse)場合、エラーを返してログインを拒否する
    // if (!friendshipData.friendFlag) {
    //   return res.status(403).json({
    //     error: 'FRIEND_REQUIRED',
    //     message: '公式アカウントを友だち追加してください。',
    //   });
    // }

    const profileRes = await fetch('https://api.line.me/v2/profile', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const profile = await profileRes.json();

    const rawLineUid = verifyData.sub;
    const hashedUserId = hashUserIdWithSaltPepper(rawLineUid);
    const customToken = await admin.auth().createCustomToken(hashedUserId);

    // 判定ロジック
    const isNavi =
      stateData.appType === 'navi' || stateData.origin.includes('navi');
    const isConnect = stateData.appType === 'connect' || !isNavi;

    const updateData = {
      lineUid: rawLineUid,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    };

    if (isNavi) updateData.isNavi = true;
    if (isConnect) updateData.isConnect = true;

    await admin
      .firestore()
      .collection('lineMessagingIds')
      .doc(hashedUserId)
      .set(updateData, { merge: true });

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

app.get('/', (req, res) => res.send('SSJO Unified Auth Server is running!'));

app.listen(PORT, () =>
  console.log(`Server running at http://localhost:${PORT}`),
);
