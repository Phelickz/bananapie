import request from 'supertest';
import App from '@/app';
import { User } from '@interfaces/users.interface';
import UserRoute from '@routes/users.route';
import AuthService from '@services/auth.service';

afterAll(async () => {
  await new Promise<void>(resolve => setTimeout(() => resolve(), 500));
});

describe('Testing Users', () => {
  describe('[GET] /users', () => {
    const authService = AuthService();
    it('response statusCode 200 / findOne', () => {
      const email = 'felixhope30@gmail';
      const findUser: User = authService.findUsers(email);
      const usersRoute = new UserRoute();
      const app = new App([usersRoute]);
      const val = '?email=';

      return request(app.getServer()).get(`${usersRoute.path}${val}${email}`).expect(200, { data: findUser, message: 'findOne' });
    });
  });
});
