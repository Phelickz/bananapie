import request from 'supertest';
import App from '@/app';
import { CreateUserDto } from '@dtos/users.dto';
import AuthRoute from '@routes/auth.route';

afterAll(async () => {
  await new Promise<void>(resolve => setTimeout(() => resolve(), 500));
});

describe('Testing Auth', () => {
  describe('[POST] /signup', () => {
    it('response should have the Create userData', () => {
      const userData: CreateUserDto = {
        email: 'felixhope30@gmail.com',
        password: 'password',
      };
      const authRoute = new AuthRoute();
      const app = new App([authRoute]);

      return request(app.getServer()).post('/signup').send(userData);
    });
  });

  describe('[POST] /login', () => {
    it('response should have the Set-Cookie header with the Authorization token', async () => {
      const userData: CreateUserDto = {
        email: 'felixhope30@gmail.com',
        password: 'password',
      };

      const authRoute = new AuthRoute();
      const app = new App([authRoute]);

      return request(app.getServer())
        .post('/login')
        .send(userData)
        .expect('Set-Cookie', /^Authorization=.+/);
    });
  });
});
