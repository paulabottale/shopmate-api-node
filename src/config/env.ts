import "dotenv/config";

type StringValue =
  | `${number}`
  | `${number}ms`
  | `${number}s`
  | `${number}m`
  | `${number}h`
  | `${number}d`;

export type ExpiresIn = number | StringValue;

export const env = {
  port: Number(process.env.PORT || 3000),
  nodeEnv: process.env.NODE_ENV || "development",
  mongoUri: process.env.MONGODB_URI || "",

  accessSecret: process.env.JWT_ACCESS_SECRET || "dev_access",
  refreshSecret: process.env.JWT_REFRESH_SECRET || "dev_refresh",

  accessTtl: (process.env.JWT_ACCESS_EXPIRES || "15m") as ExpiresIn,
  refreshTtl: (process.env.JWT_REFRESH_EXPIRES || "7d") as ExpiresIn
};
