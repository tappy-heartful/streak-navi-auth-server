import express from 'express';
import fetch from 'node-fetch';
import jwt from 'jsonwebtoken';
import cors from 'cors';

const app = express();
const PORT = process.env.PORT || 3000;

// TODO 安全な秘密鍵（本番は .env に保存して使う）
const JWT_SECRET = process.env.JWT_SECRET || '126dea4d33dd7deca8d6ee9b7870237f';
const LINE_CLIENT_ID = process.env.LINE_CLIENT_ID || '2007808275';

app.use(cors());
app.use(express.json());

// POST /verify-line-token に LINE id_token を送信
app.post('/verify-line-token', async (req, res) => {
  const idToken = req.body.idToken;
  if (!idToken) return res.status(400).json({ error: 'Missing idToken' });

  try {
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

    const userId = result.sub;

    // 独自トークンを発行（1時間有効）
    const customToken = jwt.sign({ userId }, JWT_SECRET, { expiresIn: '1h' });

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
