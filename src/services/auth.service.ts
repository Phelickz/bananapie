import { hash, compare } from 'bcrypt';
import { sign } from 'jsonwebtoken';
import { SECRET_KEY } from '@config';
import { CreateUserDto } from '@dtos/users.dto';
import { HttpException } from '@exceptions/HttpException';
import { DataStoredInToken, TokenData } from '@interfaces/auth.interface';
import { User } from '@interfaces/users.interface';
import userModel from '@models/users.model';
import { isEmpty } from '@utils/util';
import fs from 'fs';
import { createCipheriv, createDecipheriv, randomBytes, randomUUID } from 'crypto';

class AuthService {
  public users = userModel;

  public async signup(userData: CreateUserDto): Promise<User> {
    if (isEmpty(userData)) throw new HttpException(400, 'userData is empty');

    const findUser: User = await this.findUsers(userData.email);
    if (findUser) throw new HttpException(409, `This email ${userData.email} already exists`);

    const hashedPassword = await hash(userData.password, 10);
    const createUserData: User = { id: randomUUID(), ...userData, password: hashedPassword };

    const createdUser: User = await this.createUser(createUserData);

    if (!createdUser) throw new HttpException(500, 'User could not be created');

    return createdUser;
  }

  public async login2(userData: CreateUserDto): Promise<{ cookie: string; findUser: User }> {
    if (isEmpty(userData)) throw new HttpException(400, 'userData is empty');

    const findUser: User = this.users.find(user => user.email === userData.email);
    if (!findUser) throw new HttpException(409, `This email ${userData.email} was not found`);

    const isPasswordMatching: boolean = await compare(userData.password, findUser.password);
    if (!isPasswordMatching) throw new HttpException(409, 'Password is incorrect');

    const tokenData = this.createToken(findUser);
    const cookie = this.createCookie(tokenData);

    return { cookie, findUser };
  }

  public async login(userData: CreateUserDto): Promise<{ cookie: string; cookie2: string; findUser: User }> {
    if (isEmpty(userData)) throw new HttpException(400, 'userData is empty');

    const findUser: User = await this.findUsers(userData.email);
    if (!findUser) throw new HttpException(409, `This email ${userData.email} was not found`);

    const isPasswordMatching: boolean = await compare(userData.password, findUser.password);
    if (!isPasswordMatching) throw new HttpException(409, 'Password is Incorrect');

    const tokenData = this.createToken(findUser);
    const refreshToken = this.createToken(findUser);
    const cookie = this.createCookie(tokenData);
    const cookie2 = this.createCookie(refreshToken);

    return { cookie, cookie2, findUser };
  }

  public createToken(user: User): TokenData {
    const dataStoredInToken: DataStoredInToken = { email: user.email };
    const secretKey: string = SECRET_KEY;
    const expiresIn: number = 60 * 60;

    return { expiresIn, token: sign(dataStoredInToken, secretKey, { expiresIn }) };
  }

  public createCookie(tokenData: TokenData): string {
    return tokenData.token;
  }

  public async createUser(userData: User): Promise<User> {
    const data = await fs.promises.readFile('users.json', 'utf8');
    if (data) {
      const result = JSON.parse(data);
      result.users.push(userData);
      const stringifyResult = JSON.stringify(result);
      await fs.promises.writeFile('users.json', stringifyResult);
      return userData;
    }
    return null;
  }

  public async findUsers(email: String): Promise<User> {
    const data = await fs.promises.readFile('users.json', 'utf8');

    if (data) {
      const result = JSON.parse(data);

      for (let i = 0; i < result.users.length; i++) {
        if (result.users[i].email == email) {
          const foundUser: User = { email: result.users[i].email, password: result.users[i].password, id: result.users[i].id };
          return foundUser;
        }
      }
      return null;
    }
    return null;
  }

  public encryptToken(cookie: string, _secret: string): string {
    const ALGORITHM = 'aes-256-cbc';
    /**
     * Encrypt a cookie using AES 256 bits
     * @param {cookie} string the cookie we want to encrypt. Will be visible as plain string to client.
     * @param {_secret} string the secret that will be stored server-side. Client will never see this.
     */

    const iv = randomBytes(16);
    const _cipher = createCipheriv(ALGORITHM, Buffer.from(_secret), iv);
    const encrypted = [iv.toString('hex'), ':', _cipher.update(cookie, 'utf8', 'hex'), _cipher.final('hex')];
    return encrypted.join('');
  }

  private decryptCookie(cookie: string, _secret: string): string {
    const ALGORITHM = 'aes-256-cbc';
    /**
     * Decrypt a cookie using AES 256 bits
     * @param {cookie} string the cookie we want to encrypt. Will be visible as plain string to client.
     * @param {_secret} string the secret that will be stored server-side. Client will never see this.
     */

    const _encryptedArray = cookie.split(':');
    if (_encryptedArray.length !== 2) throw new Error('bad decrypt');
    const iv = new Buffer(_encryptedArray[0], 'hex');
    const encrypted = new Buffer(_encryptedArray[1], 'hex');
    ('===sss==');
    const decipher = createDecipheriv(ALGORITHM, _secret, iv);
    const decrypted = decipher.update(encrypted) + decipher.final('utf8');
    ('done1');
    return decrypted;
  }

  public verifyCsrf(requestCsrf: string, cookieCsrf: string, _secret: string): boolean {
    const resolveCookie = decodeURIComponent(requestCsrf).slice(2);
    const value = resolveCookie.split('.')[0];

    /**
     * Verify a CSRF token
     * @param {requestCsrf} string the CSRF coming from client side
     * @param {cookieCsrf} string the CSRF as stored in the user's cookies
     * @param {_secret} string the string used to encrypt the CSRF in the first place.
     */
    try {
      value;
      ('=====');
      cookieCsrf;
      const decryptedCookie = this.decryptCookie(cookieCsrf, _secret);
      const decryptedCookie2 = this.decryptCookie(value, _secret);
      ('=====');
      decryptedCookie;
      ('=====');
      decryptedCookie2;
      return decryptedCookie === decryptedCookie2;
    } catch (err) {
      return false;
    }
  }
}

export default AuthService;
