CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(30) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'user',
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    is_blocked BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS products (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    description TEXT NOT NULL,
    price NUMERIC(10, 2) NOT NULL
);

CREATE TABLE IF NOT EXISTS feedback (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id),
    message TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS security_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT REFERENCES users(id),
    username VARCHAR(30),
    event TEXT NOT NULL,
    result TEXT NOT NULL,
    ip_address INET,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS login_history (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id),
    success BOOLEAN NOT NULL,
    ip_address INET,
    login_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS security_tests (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id),
    test_name TEXT NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'Pending',
    result VARCHAR(10),
    details TEXT,
    finding TEXT,
    impact TEXT,
    evidence TEXT,
    applied_control TEXT,
    retest_result VARCHAR(10),
    risk_level VARCHAR(20),
    created_at TIMESTAMPTZ NOT NULL,
    executed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_security_logs_user ON security_logs(user_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_login_history_user ON login_history(user_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_security_tests_user ON security_tests(user_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_feedback_user ON feedback(user_id, created_at DESC);
