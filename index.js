import express from 'express';
import fetch from 'node-fetch';
import cors from 'cors';
import admin from 'firebase-admin';
import dotenv from 'dotenv';
import argon2 from 'argon2'; // ← 追加

dotenv.config(); // .env を読み込む

const app = express();
const PORT = process.env.PORT || 3000;

const LINE_CLIENT_ID = process.env.LINE_CLIENT_ID;

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

    const lineUserId = result.sub;

    // Argon2でハッシュ化してカスタムトークンのUIDに使用
    const hashedLineUserId = await argon2Hash(lineUserId);

    // Firebase Authentication のカスタムトークンを発行
    const customToken = await admin.auth().createCustomToken(hashedLineUserId);

    res.json({ customToken });
  } catch (err) {
    console.error('Server error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/', (req, res) => {
  res.send('Auth server is running!');
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});

// Argon2ハッシュ関数（UID生成用）
async function argon2Hash(input) {
  // UIDには「/」や「$」などが含まれているとFirebaseで不正扱いされるため注意
  const hash = await argon2.hash(input, {
    type: argon2.argon2id,
    timeCost: 3,
    memoryCost: 2 ** 16,
    hashLength: 32,
  });

  // Firebase UIDとして使うため、base64部分だけ抜き出して返す（簡易対応）
  // $argon2id$v=19$m=65536,t=3,p=1$[salt]$[hash] の最後の部分を取り出す
  const base64Hash = hash.split('$').pop();
  return base64Hash.replace(/\W/g, ''); // 記号を除去してUIDに使える形に整形
}
