
import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();

async function main() {
    try {
        await prisma.$connect();
        console.log('✅ Successfully connected to DB!');
    } catch (e) {
        console.error('❌ Connection failed:', e.message);
    } finally {
        await prisma.$disconnect();
    }
}

main();
