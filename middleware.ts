import { authOptions } from "@/lib/auth";
import { UserRole } from "@prisma/client";
import NextAuth from "next-auth";
import { type NextRequest, NextResponse } from "next/server";

export const publicRoutes: string[] = [];

export const authRoutes = ["/entrar", "/registrar", "/resetar-senha"];

export const defaultRedirects = {
  isNotAuthenticated: "/entrar",
  onAuthPageToLoggedUser: "/",
  onboarding: "/onboarding",
};

type NextAuthRequest = NextRequest & {
  auth?: any;
};

const { auth } = NextAuth(authOptions);

export const config = {
  matcher: [
    /*
     * Match all paths except for:
     * 1. /api/ routes
     * 2. /_next/ (Next.js internals)
     * 3. /_proxy/ (proxies for third-party services)
     * 4. Metadata files: favicon.ico, sitemap.xml, robots.txt, manifest.webmanifest
     */
    "/((?!api/|_next/|_proxy/|sw.js|swe-worker-development.js|ingest/|pagead/js/adsbygoogle.js|favicon.ico|sitemap.xml|robots.txt|manifest.webmanifest).*)",
  ],
};

export default auth(async (req: NextAuthRequest) => {
  const { nextUrl } = req;
  const { pathname } = nextUrl;

  const requestHeaders = new Headers(req.headers);
  requestHeaders.set("x-current-path", nextUrl.pathname);

  const isLogged = !!req.auth;

  let role = null;

  if (req.auth) {
    role = req.auth.user.role;
  }

  // Check route types
  const isAuthRoute = authRoutes.includes(pathname);
  const isApiRoute = pathname.startsWith("/api/");
  const isPublicRoute = publicRoutes.includes(pathname);
  const path = nextUrl.pathname;

  const response = NextResponse.next({
    request: {
      headers: requestHeaders,
    },
  });

  // Allow API routes to pass through
  if (isApiRoute) {
    return response;
  }

  // Allow public routes to pass through
  if (isPublicRoute) {
    return response;
  }

  // Handle unauthenticated users
  if (!isLogged) {
    // Allow access to auth routes
    if (isAuthRoute) {
      return response;
    }

    // Redirect to login for protected routes
    return NextResponse.redirect(
      new URL(defaultRedirects.isNotAuthenticated, nextUrl),
    );
  }

  // Redirect logged in users away from auth routes
  if (isAuthRoute) {
    return NextResponse.redirect(
      new URL(defaultRedirects.onAuthPageToLoggedUser, nextUrl),
    );
  }

  console.log("role", role);
  // Handle root path - redirect to role-specific dashboard
  if (path === "/") {
    switch (role) {
      case UserRole.ADMINISTRADOR:
        return NextResponse.rewrite(new URL("/administrador", nextUrl));
      case UserRole.GESTOR_CONTRATO:
        return NextResponse.rewrite(new URL("/gestor-contrato", nextUrl));
      case UserRole.FISCAL_ADMINISTRATIVO:
      case UserRole.FISCAL_TECNICO:
        return NextResponse.rewrite(new URL("/fiscais", nextUrl));
      case UserRole.ORDENADOR_DESPESAS:
        return NextResponse.rewrite(new URL("/ordenador-despesas", nextUrl));
      default:
        return NextResponse.rewrite(new URL("/gestor-contrato", nextUrl));
    }
  }

  // Handle role-based routing for other paths
  if (role && typeof role === "string") {
    let rolePrefix = role.toLowerCase().replace("_", "-");

    if (
      role === UserRole.FISCAL_ADMINISTRATIVO ||
      role === UserRole.FISCAL_TECNICO
    ) {
      rolePrefix = "fiscais";
    }

    // Avoid re-prefixing if the path ALREADY starts with the correct role prefix
    if (pathname.startsWith(`/${rolePrefix}/`) || pathname === `/${rolePrefix}`) {
      return response;
    }

    // Ensure pathname is not "/" here, as root path rewrites are handled earlier
    const newPath = `/${rolePrefix}${pathname === "/" ? "" : pathname}`;
    return NextResponse.rewrite(new URL(newPath, nextUrl), {
      request: { headers: requestHeaders },
    });
  }

  return response;
});
