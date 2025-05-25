-- Création de la base de données
CREATE DATABASE workshop_graphql;

-- Connexion à la base
\c workshop_graphql;

-- Table des utilisateurs
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table des rôles
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table des permissions
CREATE TABLE permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    resource VARCHAR(50) NOT NULL,
    action VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table de liaison utilisateur-rôle
CREATE TABLE user_roles (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, role_id)
);

-- Table de liaison rôle-permission
CREATE TABLE role_permissions (
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID REFERENCES permissions(id) ON DELETE CASCADE,
    granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (role_id, permission_id)
);

-- Données de test
INSERT INTO roles (id, name, description) VALUES
    ('11111111-1111-1111-1111-111111111111', 'Admin', 'Administrateur système'),
    ('22222222-2222-2222-2222-222222222222', 'User', 'Utilisateur standard'),
    ('33333333-3333-3333-3333-333333333333', 'Manager', 'Gestionnaire');

INSERT INTO permissions (id, name, description, resource, action) VALUES
    ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'users.read', 'Lire les utilisateurs', 'users', 'read'),
    ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', 'users.write', 'Modifier les utilisateurs', 'users', 'write'),
    ('cccccccc-cccc-cccc-cccc-cccccccccccc', 'users.delete', 'Supprimer les utilisateurs', 'users', 'delete'),
    ('dddddddd-dddd-dddd-dddd-dddddddddddd', 'roles.manage', 'Gérer les rôles', 'roles', 'manage');

-- Attribution des permissions aux rôles
INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('11111111-1111-1111-1111-111111111111', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'),
    ('11111111-1111-1111-1111-111111111111', 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'),
    ('11111111-1111-1111-1111-111111111111', 'cccccccc-cccc-cccc-cccc-cccccccccccc'),
    ('11111111-1111-1111-1111-111111111111', 'dddddddd-dddd-dddd-dddd-dddddddddddd'),
    ('22222222-2222-2222-2222-222222222222', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'),
    ('33333333-3333-3333-3333-333333333333', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'),
    ('33333333-3333-3333-3333-333333333333', 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb');

-- ...existing tables and data...

-- ...existing tables and permissions...

-- Utilisateurs de test
-- Mots de passe: tous utilisent "Password123!"
INSERT INTO users (id, email, password_hash, first_name, last_name) VALUES
    ('99999999-9999-9999-9999-999999999999', 'admin@test.com', '$2a$11$peIWKQW2jVf0Vam3IYAS3eUS7nJdx9Ew3XETwfIHRotoUqHTfg6v.', 'Super', 'Admin'),
    ('88888888-8888-8888-8888-888888888888', 'manager@test.com', '$2a$11$pyj84CFeHnKlbgVYq0KAeuTeVnueD/iQHFueMon13alH6chKNE8EO', 'Test', 'Manager'),
    ('77777777-7777-7777-7777-777777777777', 'user@test.com', '$2a$11$w0Fvu7Dp.Upb1IXS0yuWY.LMpWd2xjEC9AVXJ/4tgWborUcv3ATT.', 'Test', 'User');

-- Attribution des rôles aux utilisateurs de test
INSERT INTO user_roles (user_id, role_id) VALUES
    ('99999999-9999-9999-9999-999999999999', '11111111-1111-1111-1111-111111111111'), -- Admin
    ('88888888-8888-8888-8888-888888888888', '33333333-3333-3333-3333-333333333333'), -- Manager
    ('77777777-7777-7777-7777-777777777777', '22222222-2222-2222-2222-222222222222'); -- User