import compression from 'compression';
import cookieParser from 'cookie-parser';
import cookieSession from 'cookie-session';
import cors from 'cors';
import express from 'express';
import helmet from 'helmet';
import hpp from 'hpp';
import morgan from 'morgan';
import swaggerJSDoc from 'swagger-jsdoc';
import swaggerUi from 'swagger-ui-express';
import { NODE_ENV, PORT, LOG_FORMAT, ORIGIN, CREDENTIALS, SECRET_KEY } from '@config';
import { Routes } from '@interfaces/routes.interface';
import errorMiddleware from '@middlewares/error.middleware';
import { logger, stream } from '@utils/logger';
import { randomUUID } from 'crypto';
import AuthService from '@services/auth.service';
import { HttpException } from './exceptions/HttpException';

class App {
  public app: express.Application;
  public env: string;
  public port: string | number;
  public authService: Object;

  constructor(routes: Routes[]) {
    this.app = express();
    this.env = NODE_ENV || 'development';
    this.port = PORT || 3000;
    this.authService = new AuthService();

    this.initializeMiddlewares();
    this.initializeRoutes(routes);
    this.initializeSwagger();
    this.initializeErrorHandling();
  }

  public listen() {
    this.app.listen(this.port, () => {
      logger.info(`=================================`);
      logger.info(`======= ENV: ${this.env} =======`);
      logger.info(`🚀 App listening on the port ${this.port}`);
      logger.info(`=================================`);
    });
  }

  public getServer() {
    return this.app;
  }

  private initializeMiddlewares() {
    this.app.use(morgan(LOG_FORMAT, { stream }));
    this.app.use(hpp());
    this.app.use(helmet());
    this.app.use(compression());
    this.app.use(express.json());
    this.app.use(express.urlencoded({ extended: true }));
    this.app.use(cookieParser(SECRET_KEY));
    this.app.use(cors({ origin: ORIGIN, credentials: CREDENTIALS }));
    this.app.use(
      cookieSession({
        name: 'session',
        secret: SECRET_KEY,
        maxAge: 24 * 60 * 60 * 1000,
        sameSite: 'lax',
        path: '/',
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
      }),
    );
    this.app.use(function (req, res, next) {
      const value = new AuthService();
      const cookieParams = {
        httpOnly: true,
        sameSite: 'strict' as const,
        signed: true,
        maxAge: 300000,
      };
      const { csrfToken } = req.signedCookies;
      if (csrfToken === undefined && req.url !== '/signup' && req.url !== '/login') {
        throw new HttpException(401, `Your CSRF token has expired. Sign in again to generate a new token`);
      }
      if (req.url === '/signup' || req.url === '/login') {
        const token = randomUUID();
        const encryptedToken = value.encryptToken(token, SECRET_KEY);
        res.cookie('csrfToken', encryptedToken, cookieParams);
        return next();
      }
      if (csrfToken != undefined && value.verifyCsrf(req.body?._csrf, csrfToken, SECRET_KEY)) {
        res.cookie('csrfToken', csrfToken, cookieParams);
        next();
      } else {
        throw new HttpException(
          401,
          `Did not get a valid CSRF token for '${req.method} ${req.originalUrl}': ${req.body?._csrf} v. ${csrfToken}. Ensure you are adding '_csrf' as a body parameter.`,
        );
      }
    });
  }

  private initializeRoutes(routes: Routes[]) {
    routes.forEach(route => {
      this.app.use('/', route.router);
    });
  }

  private initializeSwagger() {
    const options = {
      swaggerDefinition: {
        info: {
          title: 'REST API',
          version: '1.0.0',
          description: 'Banana Api',
        },
      },
      apis: ['swagger.yaml'],
    };

    const specs = swaggerJSDoc(options);
    this.app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(specs));
  }

  private initializeErrorHandling() {
    this.app.use(errorMiddleware);
  }
}

export default App;
