-- database/schema.sql
-- Schema for the Secure Smart Environment Monitoring System (SSEMS).
-- Mirrors the database design in Chapter Three, Section 3.12.

CREATE TABLE IF NOT EXISTS Users (
    user_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username        VARCHAR(50)  NOT NULL UNIQUE,
    password_hash   VARCHAR(255) NOT NULL,
    role            VARCHAR(20)  NOT NULL DEFAULT 'user',   -- 'admin' or 'user'
    created_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login      DATETIME
);

CREATE TABLE IF NOT EXISTS Devices (
    device_id           INTEGER PRIMARY KEY AUTOINCREMENT,
    device_uid          VARCHAR(50)  NOT NULL UNIQUE,
    device_secret_hash  VARCHAR(255) NOT NULL,
    device_name         VARCHAR(100) NOT NULL,
    registered_by       INTEGER,
    status              VARCHAR(20)  NOT NULL DEFAULT 'active',  -- active | inactive | suspicious
    last_seen           DATETIME,
    last_sequence       INTEGER      NOT NULL DEFAULT 0,         -- replay-attack protection
    FOREIGN KEY (registered_by) REFERENCES Users(user_id)
);

CREATE TABLE IF NOT EXISTS SensorData (
    reading_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id       INTEGER NOT NULL,
    temperature     FLOAT   NOT NULL,
    humidity        FLOAT   NOT NULL,
    status          VARCHAR(20) NOT NULL DEFAULT 'normal',   -- normal | anomalous
    recorded_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (device_id) REFERENCES Devices(device_id)
);

CREATE TABLE IF NOT EXISTS Alerts (
    alert_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id     INTEGER,
    reading_id    INTEGER,
    alert_type    VARCHAR(50)  NOT NULL,
    severity      VARCHAR(20)  NOT NULL DEFAULT 'medium',
    message       VARCHAR(255) NOT NULL,
    resolved      BOOLEAN      NOT NULL DEFAULT 0,
    created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (device_id) REFERENCES Devices(device_id),
    FOREIGN KEY (reading_id) REFERENCES SensorData(reading_id)
);

CREATE TABLE IF NOT EXISTS AuditLogs (
    log_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_type  VARCHAR(20)  NOT NULL,   -- user | device | system
    actor_id    VARCHAR(50),
    action      VARCHAR(100) NOT NULL,
    details     TEXT,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_sensordata_device ON SensorData(device_id);
CREATE INDEX IF NOT EXISTS idx_alerts_device ON Alerts(device_id);
CREATE INDEX IF NOT EXISTS idx_auditlogs_created ON AuditLogs(created_at);
