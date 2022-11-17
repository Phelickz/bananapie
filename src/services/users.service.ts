import { HttpException } from '@exceptions/HttpException';
import { User } from '@interfaces/users.interface';
import userModel from '@models/users.model';
import AuthService from './auth.service';

class UserService {
  public users = userModel;
  private authService = new AuthService();

  public async findUserByEmail(email: string): Promise<User> {
    const findUser: User = await this.authService.findUsers(email);
    if (!findUser) throw new HttpException(409, "User doesn't exist");

    return findUser;
  }
}

export default UserService;
