import 'dotenv/config';
import bcrypt from 'bcryptjs';
import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
);

const DEMO_USERS = [
  { email: 'admin@phishscan.com',   password: 'Admin123!',   role: 'admin'   },
  { email: 'analyst@phishscan.com', password: 'Analyst123!', role: 'analyst' },
  { email: 'auditor@phishscan.com', password: 'Auditor123!', role: 'auditor' },
];

async function seed() {
  console.log('Seeding demo users...');
  for (const u of DEMO_USERS) {
    const password_hash = await bcrypt.hash(u.password, 12);
    const { error } = await supabase
      .from('users')
      .upsert({ email: u.email, password_hash, role: u.role }, { onConflict: 'email' });
    if (error) {
      console.error(`  ✗ ${u.email}: ${error.message}`);
    } else {
      console.log(`  ✓ ${u.role}: ${u.email} / ${u.password}`);
    }
  }
  console.log('Done.');
}

seed().then(() => process.exit(0)).catch(e => { console.error(e); process.exit(1); });
