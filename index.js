import express from 'express';
import fetch from 'node-fetch';
import cors from 'cors';
import admin from 'firebase-admin';
import dotenv from 'dotenv';
import crypto from 'crypto'; // 先頭に追加

dotenv.config(); // .env を読み込む

const app = express();
const PORT = process.env.PORT || 3000;

const LINE_CLIENT_ID = process.env.LINE_CLIENT_ID;
const LINE_CLIENT_SECRET = process.env.LINE_CLIENT_SECRET;

// Firebase Admin 初期化（サービスアカウントJSONファイルを使う）
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, '\n');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

app.use(cors());
app.use(express.json());

// POST /verify-line-token に LINE id_token を送信
app.post('/verify-line-token', async (req, res) => {
  const idToken = req.body.idToken;
  if (!idToken) return res.status(400).json({ error: 'Missing idToken' });

  try {
    // LINEのid_tokenを検証
    const response = await fetch('https://api.line.me/oauth2/v2.1/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        id_token: idToken,
        client_id: LINE_CLIENT_ID,
      }),
    });

    const result = await response.json();

    if (result.error) {
      console.error('LINE token verify failed:', result);
      return res.status(401).json({ error: 'Invalid LINE token' });
    }

    // ここから追加検証
    // audienceが正しいLINEクライアントIDであること

    if (result.aud !== LINE_CLIENT_ID) {
      console.error('Invalid aud in ID token:', result.aud);
      return res.status(401).json({ error: 'Invalid aud in ID token' });
    }

    // トークンが有効期限内であること;
    const now = Math.floor(Date.now() / 1000);
    if (typeof result.exp !== 'number' || result.exp < now) {
      console.error('ID token expired:', result.exp);
      return res.status(401).json({ error: 'ID token expired' });
    }

    // 発行者がLINE公式であること;
    const validIssuers = ['https://access.line.me', 'https://access.line.me/'];
    if (!validIssuers.includes(result.iss)) {
      console.error('Invalid iss in ID token:', result.iss);
      return res.status(401).json({ error: 'Invalid iss in ID token' });
    }
    // ここまで追加検証

    const lineUserId = result.sub; // LINEのユーザー固有ID

    // ハッシュ化してカスタムトークン発行
    const hashedLineUserId = sha256(lineUserId);
    const customToken = await admin.auth().createCustomToken(hashedLineUserId);

    res.json({ customToken });
  } catch (err) {
    console.error('Server error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/exchange-line-token', async (req, res) => {
  try {
    const { code, redirectUri } = req.body;

    if (!code || !redirectUri) {
      return res.status(400).json({ error: 'Missing code or redirectUri' });
    }

    // LINEのアクセストークン取得APIへPOSTリクエスト
    const response = await fetch('https://api.line.me/oauth2/v2.1/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: redirectUri,
        client_id: LINE_CLIENT_ID,
        client_secret: LINE_CLIENT_SECRET,
      }),
    });

    if (!response.ok) {
      const errorBody = await response.text();
      console.error('LINE token exchange error:', errorBody);
      return res.status(500).json({ error: 'Failed to exchange token' });
    }

    const tokenData = await response.json();

    // 取得したアクセストークン、IDトークンをそのまま返す（必要に応じてIDトークンの検証も可能）
    res.json(tokenData);
  } catch (err) {
    console.error('Server error on token exchange:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/', (req, res) => {
  res.send('Auth server is running!');
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});

// ハッシュ関数
function sha256(input) {
  return crypto.createHash('sha256').update(input).digest('hex');
}
