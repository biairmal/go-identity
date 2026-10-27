-- +goose Up

-- A Google flow started from GET /v1/auth/google/link/start links the Google
-- account to this signed-in user instead of signing anyone in.
ALTER TABLE oauth_states ADD COLUMN link_user_id uuid REFERENCES users(id);

-- +goose Down
ALTER TABLE oauth_states DROP COLUMN link_user_id;
