import JWT from 'jsonwebtoken';
import { Request, Response, NextFunction } from 'express';
import { NotAuthorizedError } from './error-handler';

const tokens: string[] = [
  'auth',
  'seller',
  'gig',
  'buyer',
  'message',
  'order',
  'review',
];

export const verifyGatewayRequest = (
  req: Request,
  _res: Response,
  next: NextFunction
): void => {
  if (!req.headers?.gatewaytoken) {
    throw new NotAuthorizedError(
      'Invalid Request',
      'verifyGatewayRequest() method: Request not coming from api gateway'
    );
  }

  const token: string = req.headers?.gatewayToken as string;
  if (!tokens.includes(token)) {
    throw new NotAuthorizedError(
      'Invalid Request',
      'verifyGatewayRequest() method: Request not coming from api gateway'
    );
  }

  try {
    const payload: { id: string; iat: number } = JWT.verify(
      token,
      '2275e09a4274b8a5928acc72f2f2e53a'
    ) as {
      id: string;
      iat: number;
    };

    if (!tokens.includes(payload.id)) {
      throw new NotAuthorizedError(
        'Invalid Request',
        'verifyGatewayRequest() method: Request payload is invalid'
      );
    }
  } catch (error) {
    throw new NotAuthorizedError(
      'Invalid Request',
      'verifyGatewayRequest() method: Request not coming from api gateway'
    );
  }
  next();
};
