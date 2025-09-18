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
const FIXED_SALT = process.env.SALT; // 固定ソルト（環境変数から）
const FIXED_PEPPER = process.env.PEPPER; // 固定ペッパー（環境変数から）

// Firebase Admin 初期化（サービスアカウントJSONファイルを使う）
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, '\n');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// --- CORS設定 ---
app.use(cors());

// JSONパース
app.use(express.json());

// SALT + PEPPER でハッシュ化
function hashUserIdWithSaltPepper(userId) {
  return crypto
    .createHash('sha256')
    .update(FIXED_SALT + userId + FIXED_PEPPER)
    .digest('hex');
}

// POST LINEログインし、カスタムトークンとプロフィール情報を返却する
app.post('/line-login', async (req, res) => {
  const { code, redirectUri } = req.body;
  if (!code || !redirectUri) {
    return res.status(400).json({ error: 'Missing code or redirectUri' });
  }

  try {
    // 1. LINE アクセストークン取得
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

    // 2. IDトークン検証
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

    // 3. プロフィール取得
    const profileRes = await fetch('https://api.line.me/v2/profile', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const profile = await profileRes.json();

    // 4. 環境変数の固定SALT+PEPPERでハッシュ化
    const hashedUserId = hashUserIdWithSaltPepper(verifyData.sub);

    // 5. Firebase カスタムトークン作成
    const customToken = await admin.auth().createCustomToken(hashedUserId);

    // 6. フロントへ返す
    res.json({ customToken, profile });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/', (req, res) => {
  res.send('Auth server is running!');
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
