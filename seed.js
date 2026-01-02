import 'dotenv/config';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

async function main() {
    console.log('🌱 Starting seed...');

    // Cleanup existing data
    await prisma.rating.deleteMany({});
    await prisma.jobRequest.deleteMany({});
    await prisma.user.deleteMany({});

    // 1. Create Waiter (The user we login as: 0501234567)
    const waiterPassword = await bcrypt.hash('123456', 10);
    const waiter = await prisma.user.create({
        data: {
            phone: '0501234567',
            password: waiterPassword,
            full_name: 'ישראל ישראלי',
            email: 'israel@example.com',
            roles: JSON.stringify(['waiter', 'bartender']),
            city: 'תל אביב',
            region: 'center',
            price_per_event: 400,
            role_prices: JSON.stringify({ waiter: 400, bartender: 450 }),
            bio: 'מלצר מנוסה וחרוץ, עובד באירועים כבר 3 שנים.',
            experience_years: 3,
            available: true
        }
    });

    // 2. Create Event Manager
    const managerPassword = await bcrypt.hash('123456', 10);
    const manager = await prisma.user.create({
        data: {
            phone: '0509999999',
            password: managerPassword,
            full_name: 'דני מפיק',
            email: 'dani@events.com',
            roles: JSON.stringify(['event_manager']),
            city: 'הרצליה',
            region: 'center'
        }
    });

    // 3. Create Job Requests

    // Request 1: Pending (Received by Waiter)
    await prisma.jobRequest.create({
        data: {
            waiter_id: waiter.id,
            event_manager_id: manager.id,
            event_date: new Date(Date.now() + 86400000 * 2), // 2 days from now
            event_location: 'אולמי השרון, הרצליה',
            price_offered: 450,
            event_type: 'חתונה',
            notes: 'נדרש קוד לבוש שחור מלא',
            status: 'pending',
            requested_role: 'waiter'
        }
    });

    // Request 2: Accepted (Upcoming)
    await prisma.jobRequest.create({
        data: {
            waiter_id: waiter.id,
            event_manager_id: manager.id,
            event_date: new Date(Date.now() + 86400000 * 5), // 5 days from now
            event_location: 'גן האירועים, תל אביב',
            price_offered: 500,
            event_type: 'בר מצווה',
            status: 'accepted',
            requested_role: 'bartender'
        }
    });

    // Request 3: Completed (Past)
    await prisma.jobRequest.create({
        data: {
            waiter_id: waiter.id,
            event_manager_id: manager.id,
            event_date: new Date(Date.now() - 86400000 * 5), // 5 days ago
            event_location: 'מרכז הכנסים',
            price_offered: 400,
            event_type: 'כנס עסקי',
            status: 'completed',
            requested_role: 'waiter'
        }
    });

    console.log('✅ Seed completed! Created waiter, manager, and 3 jobs.');
}

main()
    .catch((e) => {
        console.error(e);
        process.exit(1);
    })
    .finally(async () => {
        await prisma.$disconnect();
    });
