import { NextFunction, Request, Response } from 'express';
import { User } from '@interfaces/users.interface';
import userService from '@services/users.service';

class UsersController {
  public userService = new userService();

  public getUserByEmail = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const email = String(req.query.email);
      const findOneUserData: User = await this.userService.findUserByEmail(email);

      res.status(200).json({ data: findOneUserData, message: 'findOne' });
    } catch (error) {
      next(error);
    }
  };
}

export default UsersController;
