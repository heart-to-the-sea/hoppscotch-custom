import {
  Body,
  Controller,
  Get,
  Post,
  Query,
  Req,
  Request,
  Res,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignInMagicDto } from './dto/signin-magic.dto';
import { VerifyMagicDto } from './dto/verify-magic.dto';
import { Response } from 'express';
import * as E from 'fp-ts/Either';
import { RTJwtAuthGuard } from './guards/rt-jwt-auth.guard';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { GqlUser } from 'src/decorators/gql-user.decorator';
import { AuthUser } from 'src/types/AuthUser';
import { AuthProvider, authCookieHandler, authProviderCheck } from './helper';
import { ThrottlerBehindProxyGuard } from 'src/guards/throttler-behind-proxy.guard';
import { AUTH_PROVIDER_NOT_SPECIFIED } from 'src/errors';
import { ConfigService } from '@nestjs/config';
import { throwHTTPErr } from 'src/utils';
import { UserLastLoginInterceptor } from 'src/interceptors/user-last-login.interceptor';

@UseGuards(ThrottlerBehindProxyGuard)
@Controller({ path: 'auth', version: '1' })
export class AuthController {
  constructor(
    private authService: AuthService,
    private configService: ConfigService,
  ) {}

  @Get('providers')
  async getAuthProviders() {
    const providers = await this.authService.getAuthProviders();
    return { providers };
  }

  /**
   ** Route to initiate magic-link auth for a users email
   */
  @Post('signin')
  async signInMagicLink(
    @Body() authData: SignInMagicDto,
    @Query('origin') origin: string,
  ) {
    if (
      !authProviderCheck(
        AuthProvider.EMAIL,
        this.configService.get('INFRA.VITE_ALLOWED_AUTH_PROVIDERS'),
      )
    ) {
      throwHTTPErr({ message: AUTH_PROVIDER_NOT_SPECIFIED, statusCode: 404 });
    }

    const deviceIdToken = await this.authService.signInMagicLink(
      authData.email,
      origin,
    );
    if (E.isLeft(deviceIdToken)) throwHTTPErr(deviceIdToken.left);
    return deviceIdToken.right;
  }

  /**
   * 账户登陆
   * @param data
   */
  @Post('siginUserAndPass')
  async siginUserAndPass(
    @Body() data: { user: string; pass: string },
    // @Query('origin') origin: string
    @Res() res: Response,
  ) {
    console.log(data);
    const authTokens = await this.authService.signInUserAndPass(data);
    if (E.isLeft(authTokens)) throwHTTPErr(authTokens.left);
    res.status(200).json(authTokens.right).send();
  }
  @Get('daemonList')
  async daemonList(@Res() res: Response) {
    const authTokens = await this.authService.daemonList();
    res.status(200).json(authTokens).send();
  }

  /**
   ** Route to verify and sign in a valid user via magic-link
   */
  @Post('verify')
  async verify(@Body() data: VerifyMagicDto, @Res() res: Response) {
    const authTokens = await this.authService.verifyMagicLinkTokens(data);
    if (E.isLeft(authTokens)) throwHTTPErr(authTokens.left);
    console.log(authTokens.right);
    authCookieHandler(res, authTokens.right, false, null);
  }

  /**
   ** Route to refresh auth tokens with Refresh Token Rotation
   * @see https://auth0.com/docs/secure/tokens/refresh-tokens/refresh-token-rotation
   */
  @Get('refresh')
  // @UseGuards(RTJwtAuthGuard)
  async refresh(@GqlUser() user: AuthUser, @Req() req: Request, @Res() res) {
    console.log('refhresh');
    // const refreshToken = req.headers['refresh_token'];
    // const authTokens = await this.authService.refreshAuthTokens(
    //   refreshToken,
    //   user,
    // );
    // if (E.isLeft(authTokens)) throwHTTPErr(authTokens.left);
    // res.status(200).json(authTokens.right).send();
    res.status(200).send();
  }

  /**
   ** Log user out by clearing cookies containing auth tokens
   */
  @Get('logout')
  async logout(@Res() res: Response) {
    console.log('logout===========>')
    res.clearCookie('access_token');
    res.clearCookie('refresh_token');
    return res.status(200).send();
  }

  @Get('verify/admin')
  @UseGuards(JwtAuthGuard)
  async verifyAdmin(@GqlUser() user: AuthUser) {
    const userInfo = await this.authService.verifyAdmin(user);
    if (E.isLeft(userInfo)) throwHTTPErr(userInfo.left);
    return userInfo.right;
  }

  @Get('desktop')
  @UseGuards(JwtAuthGuard)
  @UseInterceptors(UserLastLoginInterceptor)
  async desktopAuthCallback(
    @GqlUser() user: AuthUser,
    @Query('redirect_uri') redirectUri: string,
  ) {
    if (!redirectUri || !redirectUri.startsWith('http://localhost')) {
      throwHTTPErr({
        message: 'Invalid desktop callback URL',
        statusCode: 400,
      });
    }

    const tokens = await this.authService.generateAuthTokens(user.uid);
    if (E.isLeft(tokens)) throwHTTPErr(tokens.left);

    return tokens.right;
  }
}
