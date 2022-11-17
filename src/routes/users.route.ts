import { Router } from 'express';
import UsersController from '@controllers/users.controller';
import { Routes } from '@interfaces/routes.interface';
import authMiddleware from '@/middlewares/auth.middleware';

class UsersRoute implements Routes {
  public path = '/users';
  public router = Router();
  public usersController = new UsersController();

  constructor() {
    this.initializeRoutes();
  }

  private initializeRoutes() {
    this.router.get(`${this.path}`, authMiddleware, this.usersController.getUserByEmail);
  }
}

export default UsersRoute;
