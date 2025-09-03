import logger from 'pino';
import dayjs from 'dayjs';

/**
 * Logs incoming request info
 */
export const requestLogger = (request, response, next) => {
  console.log('Method:', request.method);
  console.log('Path:  ', request.path);
  console.log('Body:  ', request.body);
  console.log('Cookies: ', request.cookies);
  console.log('Headers: ',  request.headers);
  console.log('---');
  next();
};

/**
 * Handler for unknown routes
 */
export const unknownEndpoint = (request, response) => {
  response.status(404).send({ error: 'unknown endpoint' });
};

/**
 * Error handling middleware
 */
export const errorHandler = (error, request, response, next) => {
  console.error(error.message);

  if (error.name === 'CastError') {
    return response.status(400).send({ error: 'malformatted id' });
  } else if (error.name === 'ValidationError') {
    return response.status(400).json({ error: error.message });
  }

  next(error);
};

/**
 * Pino logger instance with pretty output and custom timestamp
 */
const log = logger({
  transport: {
    target: 'pino-pretty',
    options: {
      colorize: true
    }
  },
  timestamp: () => `,"time":"${dayjs().format()}"`
});

export default log;
