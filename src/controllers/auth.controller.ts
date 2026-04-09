import type { Request, Response } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { User } from "../models/User";
import { registerSchema } from "../schemas/auth.schema";
import { env } from "../config/env";

type AnyPayload = string | Buffer | object;


const signJwt = (
  payload: AnyPayload,
  secret: string,
  expiresIn: string | number
): string => {
  return (jwt as any).sign(payload, secret, { expiresIn }) as string;
};

function signAccess(userId: string, role: string) {
  return signJwt(
    { sub: userId, role },
    env.accessSecret,
    env.accessTtl
  );
}

function signRefresh(userId: string, role: string) {
  return signJwt(
    { sub: userId, role },
    env.refreshSecret,
    env.refreshTtl
  );
}


export async function register(req: Request, res: Response) {
  const parsed = registerSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json(parsed.error.flatten());
  }

  const { email, password } = parsed.data;

  const exists = await User.findOne({ email });
  if (exists) {
    return res.status(409).json({ error: "Email already registered" });
  }

  const passwordHash = await bcrypt.hash(password, 10);

  const user = await User.create({
    email,
    passwordHash,
    role: "USER"
  });

  const accessToken = signAccess(user.id, user.role);
  const refreshToken = signRefresh(user.id, user.role);

  return res.status(201).json({
    user: {
      id: user.id,
      email: user.email,
      role: user.role
    },
    accessToken,
    refreshToken
  });
}


export async function login(req: Request, res: Response) {
  const { email, password } = req.body as {
    email?: string;
    password?: string;
  };

  if (!email || !password) {
    return res
      .status(400)
      .json({ error: "Email and password are required" });
  }

  const user = await User.findOne({ email });
  if (!user) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const match = await bcrypt.compare(password, user.passwordHash);
  if (!match) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const accessToken = signAccess(user.id, user.role);
  const refreshToken = signRefresh(user.id, user.role);

  return res.json({
    user: {
      id: user.id,
      email: user.email,
      role: user.role
    },
    accessToken,
    refreshToken
  });
}

export async function refresh(req: Request, res: Response) {
  const { refreshToken } = req.body as { refreshToken?: string };

  if (!refreshToken) {
    return res.status(400).json({ error: "refreshToken is required" });
  }

  try {
    const payload = (jwt as any).verify(
      refreshToken,
      env.refreshSecret
    ) as { sub: string; role: string };

    const newAccess = signAccess(payload.sub, payload.role);
    const newRefresh = signRefresh(payload.sub, payload.role);

    return res.json({
      accessToken: newAccess,
      refreshToken: newRefresh
    });
  } catch (err) {
    return res.status(401).json({ error: "Invalid refresh token" });
  }
}
