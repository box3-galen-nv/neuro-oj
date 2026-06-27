import { Hono } from "hono";
import { adminMiddleware, authMiddleware } from "../middleware/auth.ts";
import {
  getUserProfile,
  listUsers,
  loginUser,
  promoteUser,
  registerUser,
} from "../services/auth.ts";
import { requestReset, resetPassword } from "../services/passwordReset.ts";
import { BadRequestError, ValidationError } from "../lib/errors.ts";
import { parseJsonBody } from "../lib/request.ts";
import type {
  ForgotPasswordInput,
  LoginInput,
  RegisterInput,
  ResetPasswordInput,
} from "../types/auth.ts";

const auth = new Hono<{ Variables: { userId: string; userRole: string } }>();

/**
 * 用户注册端点。
 * POST /api/v1/auth/register
 */
auth.post("/register", async (c) => {
  const body = await parseJsonBody<RegisterInput>(c);

  // 验证必填字段
  if (!body.username || !body.email || !body.password) {
    const missing: string[] = [];
    if (!body.username) missing.push("username");
    if (!body.email) missing.push("email");
    if (!body.password) missing.push("password");
    throw new ValidationError(
      `缺少必填字段：${missing.join(", ")}`,
    );
  }

  // 验证用户名格式（3-30 字符，仅字母、数字、下划线）
  if (!/^[a-zA-Z0-9_]{3,30}$/.test(body.username)) {
    throw new ValidationError("用户名仅允许字母、数字和下划线，长度 3-30");
  }

  // 验证邮箱格式
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(body.email)) {
    throw new ValidationError("邮箱格式不正确");
  }

  // 验证密码长度
  if (body.password.length < 8) {
    throw new ValidationError("密码长度不能少于 8 位");
  }

  const user = await registerUser(body);
  return c.json({ data: user }, 201);
});

/**
 * 用户登录端点。
 * POST /api/v1/auth/login
 */
auth.post("/login", async (c) => {
  const body = await parseJsonBody<LoginInput>(c);

  // 验证必填字段
  if (!body.login || !body.password) {
    throw new ValidationError("缺少必填字段：login, password");
  }

  const result = await loginUser(body);
  return c.json({ data: result }, 200);
});

/**
 * 获取当前用户信息端点。
 * GET /api/v1/auth/me
 * 需要 Bearer token 认证。
 */
auth.get("/me", authMiddleware, async (c) => {
  const userId = c.get("userId") as string;
  const user = await getUserProfile(userId);
  return c.json({ data: user }, 200);
});

/**
 * 密码重置请求端点（issue #49）。
 * POST /api/v1/auth/forgot-password
 *
 * 防枚举行为：不管邮箱是否存在，统一返 200 + 同一消息。
 * 邮箱存在时生成 token + 调 sendPasswordResetEmail()（mock 模式打印到 stdout）。
 */
auth.post("/forgot-password", async (c) => {
  const body = await parseJsonBody<ForgotPasswordInput>(c);

  if (!body.email) {
    throw new BadRequestError("缺少字段 email");
  }

  // 应用基础 URL：从请求头 Host 拼出（生产环境后续接 APP_URL 环境变量）
  const proto = c.req.header("x-forwarded-proto") ?? "http";
  const host = c.req.header("host") ?? "localhost:3000";
  const appBaseUrl = `${proto}://${host}`;

  await requestReset(body.email, appBaseUrl);

  return c.json(
    {
      ok: true,
      message: "如果该邮箱已注册，您将收到一封密码重置邮件",
    },
    200,
  );
});

/**
 * 密码重置执行端点（issue #49）。
 * POST /api/v1/auth/reset-password
 *
 * 用邮件链接中的 token + 新密码重置密码。
 * 令牌无效/过期/已用时返 400 明确错误（用户主动操作场景）。
 */
auth.post("/reset-password", async (c) => {
  const body = await parseJsonBody<ResetPasswordInput>(c);

  if (!body.token || !body.new_password) {
    const missing: string[] = [];
    if (!body.token) missing.push("token");
    if (!body.new_password) missing.push("new_password");
    throw new BadRequestError(`缺少字段：${missing.join(", ")}`);
  }

  await resetPassword(body.token, body.new_password);

  return c.json(
    {
      ok: true,
      message: "密码重置成功，请使用新密码登录",
    },
    200,
  );
});

/**
 * 管理员用户管理路由。
 * 需要 authMiddleware + adminMiddleware 双重保护。
 */
const adminAuth = new Hono<
  { Variables: { userId: string; userRole: string } }
>();

/**
 * 管理员获取用户列表（分页）。
 * GET /api/v1/admin/users
 */
adminAuth.get(
  "/users",
  authMiddleware,
  adminMiddleware,
  async (c) => {
    let page = parseInt(c.req.query("page") ?? "1", 10);
    let perPage = parseInt(c.req.query("per_page") ?? "20", 10);
    if (isNaN(page) || page < 1) page = 1;
    if (isNaN(perPage) || perPage < 1) perPage = 20;
    if (perPage > 100) perPage = 100;

    const result = await listUsers({ page, perPage });
    return c.json({ data: result.data, pagination: result.pagination });
  },
);

/**
 * 管理员提升/降级用户角色。
 * PATCH /api/v1/admin/users/:id/role
 */
adminAuth.patch(
  "/users/:id/role",
  authMiddleware,
  adminMiddleware,
  async (c) => {
    const targetUserId = c.req.param("id") as string;
    const body = await parseJsonBody<{ role: string }>(c);

    if (!body.role) {
      throw new ValidationError("缺少必填字段：role");
    }

    const user = await promoteUser(targetUserId, body.role, c.get("userId"));
    return c.json({ data: user }, 200);
  },
);

export { adminAuth };
export default auth;
