import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { User } from '@prisma/client';
import { Request, Response } from 'express';
import { PrismaService } from 'src/prisma.service';
import { LoginDto, RegisterDto } from './dto';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly prisma: PrismaService,
    private readonly configService: ConfigService,
  ) {}

  async refreshToken(req: Request, res: Response) {
    const refreshToken = req.cookies['refresh_token'];

    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token not found');
    }
    let payload;
    try {
      payload = this.jwtService.verify(refreshToken, {
        secret: this.configService.get<string>('REFRESH_TOKEN_SECRET'),
        //REFRESH_TOKEN_SECRET => env
      });
    } catch (error) {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }
    const userExits = await this.prisma.user.findUnique({
      where: { id: payload.sub },
      //payload.sub => sub is something like ID
    });
    if (!userExits) {
      //if there's no user
      throw new BadRequestException('User no longer exits');
    }
    const expiresIn = 15000;
    const expiration = Math.floor(Date.now() / 1000) + expiresIn;
    const accessToken = this.jwtService.sign(
      { ...payload, exp: expiration },
      { secret: this.configService.get('ACCESS_TOKEN_SECRET') },
    );
    res.cookie('access_token', accessToken, { httpOnly: true });
    return accessToken;
  }
  private async issueToken(user: User, response: Response) {
    const payload = { username: user.fullname, sub: user.id };
    const accessToken = this.jwtService.sign(
      { ...payload },
      {
        secret: this.configService.get<string>('ACCESS_TOKEN_SECRET'),
        expiresIn: '7d',
      },
    );

    response.cookie('access_token', accessToken, { httpOnly: true });
    response.cookie('refresh_token', accessToken, { httpOnly: true });

    return { user };
  }

  async validateUser(loginDto: LoginDto) {
    const user = await this.prisma.user.findUnique({
      where: { email: loginDto.email },
    });
    const comparePassword = await bcrypt.compare(
      loginDto.password,
      user.password,
    );

    if (user && comparePassword) {
      return user;
    }
    return null;
  }

  async register(registerDto: RegisterDto, response: Response) {
    const exitingUser = await this.prisma.user.findUnique({
      where: { email: registerDto.email },
    });
    if (exitingUser) {
      throw new BadRequestException({ email: 'Email already in use' });
    }

    const hashPassword = await bcrypt.hash(registerDto.password, 10);
    const user = await this.prisma.user.create({
      data: {
        fullname: registerDto.fullname,
        password: hashPassword,
        email: registerDto.email,
      },
    });
    return this.issueToken(user, response);
  }

  async login(loginDto: LoginDto, response: Response) {
    const user = await this.validateUser(loginDto);
    if (!user) {
      throw new BadRequestException({
        invalid: 'Invalid credentials',
      });
    }
    return this.issueToken(user, response);
  }
  async logout(response: Response) {
    response.clearCookie('access_token');
    response.clearCookie('refresh_token');
    return 'Successfully logged out';
  }
}
