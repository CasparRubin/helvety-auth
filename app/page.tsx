import { redirect } from "next/navigation";

import { createClient } from "@/lib/supabase/server";

export default async function Home() {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (user) {
    // Authenticated users go to main site in production
    if (process.env.NODE_ENV === "production") {
      redirect("https://helvety.com");
    }
    // In development, authenticated users go to login page (which will show logged-in state)
  }

  // All users (authenticated in dev, unauthenticated everywhere) go to login
  redirect("/login");
}
