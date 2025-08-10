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

// ランダムソルト生成関数
function generateSalt(length = 16) {
  return crypto.randomBytes(length).toString('hex');
}

// ソルト付きハッシュ化
function sha256WithSalt(input, salt) {
  return crypto
    .createHash('sha256')
    .update(input + salt)
    .digest('hex');
}

// LINEのユーザーIDを受け取ってハッシュ化した値をドキュメントIDとして使う例
function hashUserId(lineUserId) {
  return crypto.createHash('sha256').update(lineUserId).digest('hex');
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

    // // 4. saltDocIdを取得
    // const saltDocId = await getUserSaltDocId(verifyData.sub);

    // // 5. ソルト取得または生成
    // const saltDocRef = firestore.collection('userSalts').doc(saltDocId);
    // const saltDoc = await saltDocRef.get();

    // let salt;
    // if (saltDoc.exists) {
    //   salt = saltDoc.data().salt;
    // } else {
    //   salt = generateSalt();
    //   await saltDocRef.set({ salt });
    // }

    // // 6. ソルト付きハッシュ化
    // const hashedLineUserId = sha256WithSalt(verifyData.sub, salt);

    // // 7. Firebase カスタムトークン作成
    // const customToken = await admin.auth().createCustomToken(hashedLineUserId);
    // 5. ソルト取得または生成
    const hashedUserId = hashUserId(verifyData.sub);

    const userSaltDocRef = admin
      .firestore()
      .collection('userSalts')
      .doc(hashedUserId);
    const userSaltDoc = await userSaltDocRef.get();

    let salt;
    if (userSaltDoc.exists) {
      salt = userSaltDoc.data().salt;
    } else {
      salt = generateSalt();
      await userSaltDocRef.set({ salt });
    }

    // 6. ソルト付きハッシュ化
    const saltedHashedId = sha256WithSalt(verifyData.sub, salt);

    // 7. Firebase カスタムトークン作成
    const customToken = await admin.auth().createCustomToken(saltedHashedId);

    // 8. フロントへ返す（トークン類は返さない）
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
