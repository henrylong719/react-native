import 'src/db';
import express from 'express';
import authRouter from 'routes/auth';
import dotenv from 'dotenv';
dotenv.config();

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// API Routes
app.use('/auth', authRouter);

app.listen(8000, () => {
  console.log('The app is running on http://localhost:8000');
});
