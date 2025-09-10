import express from 'express';
import 'dotenv/config';
import cors from 'cors';
import routes from './routes.js';
import connectDB from './db/db.js';
import { requestLogger } from './utils/requestLogger.js';
import cookieParser from 'cookie-parser';

const port = parseInt(process.env.PORT) || 3001;
const host = process.env.HOST  || '0.0.0.0';

const app = express();

app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(requestLogger);

const allowedOrigins = [
  process.env.FRONTEND_URL,     
  process.env.DOCKER_FRONTEND_URL,
  'http://localhost:7200',
  'http://127.0.0.1:7200',
].filter(Boolean);

app.use(
  cors({
    origin(origin, cb) {
      if (!origin) return cb(null, true);
      if (allowedOrigins.includes(origin)) return cb(null, true);
      return cb(new Error(`CORS blocked for origin: ${origin}`));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  })
);





// Simulating 1s delay
// app.use(function(req,res,next){
//   setTimeout(next, 1000)
// });
routes(app);

app.listen(port, host, async () => {
  await connectDB();
  console.log(`Server running at ${host}:${port}`);
});

app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && "body" in err) {
    const formattedError = {
      status: 400,
      message: err.message,
    };
    return res.status(400).json(formattedError);
  }
  next();
});
