-- CreateTable
CREATE TABLE "User" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "phone" TEXT NOT NULL,
    "password" TEXT,
    "full_name" TEXT,
    "email" TEXT,
    "profile_image" TEXT,
    "roles" TEXT,
    "city" TEXT,
    "region" TEXT,
    "price_per_event" REAL,
    "role_prices" TEXT,
    "bio" TEXT,
    "experience_years" INTEGER,
    "available" BOOLEAN NOT NULL DEFAULT true,
    "created_at" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "verification_code" TEXT,
    "verification_code_expires" DATETIME
);

-- CreateTable
CREATE TABLE "JobRequest" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "waiter_id" INTEGER NOT NULL,
    "event_manager_id" INTEGER NOT NULL,
    "event_date" DATETIME NOT NULL,
    "event_location" TEXT,
    "price_offered" REAL,
    "event_type" TEXT,
    "notes" TEXT,
    "status" TEXT NOT NULL DEFAULT 'pending',
    "requested_role" TEXT,
    "cancellation_reason" TEXT,
    "created_date" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "JobRequest_waiter_id_fkey" FOREIGN KEY ("waiter_id") REFERENCES "User" ("id") ON DELETE RESTRICT ON UPDATE CASCADE,
    CONSTRAINT "JobRequest_event_manager_id_fkey" FOREIGN KEY ("event_manager_id") REFERENCES "User" ("id") ON DELETE RESTRICT ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "Rating" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "waiter_id" INTEGER NOT NULL,
    "event_manager_id" INTEGER NOT NULL,
    "job_request_id" INTEGER NOT NULL,
    "rating" INTEGER NOT NULL,
    "review" TEXT,
    "created_at" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "Rating_waiter_id_fkey" FOREIGN KEY ("waiter_id") REFERENCES "User" ("id") ON DELETE RESTRICT ON UPDATE CASCADE,
    CONSTRAINT "Rating_event_manager_id_fkey" FOREIGN KEY ("event_manager_id") REFERENCES "User" ("id") ON DELETE RESTRICT ON UPDATE CASCADE,
    CONSTRAINT "Rating_job_request_id_fkey" FOREIGN KEY ("job_request_id") REFERENCES "JobRequest" ("id") ON DELETE RESTRICT ON UPDATE CASCADE
);

-- CreateIndex
CREATE UNIQUE INDEX "User_phone_key" ON "User"("phone");

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");

-- CreateIndex
CREATE UNIQUE INDEX "Rating_job_request_id_key" ON "Rating"("job_request_id");
