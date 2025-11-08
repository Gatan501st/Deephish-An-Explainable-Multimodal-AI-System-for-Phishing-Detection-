-- DeepPhish Database Schema for Supabase
-- Run this in Supabase SQL Editor

-- Organizations Table (must be created first as user_profiles references it)
CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    domain TEXT,
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Analysis History Table
CREATE TABLE IF NOT EXISTS analysis_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    analysis_type TEXT NOT NULL, -- 'full', 'nlu', 'url', 'attachment'
    input_data JSONB, -- Original input (email text, URL, etc.)
    result_data JSONB NOT NULL, -- Full analysis result
    risk_level TEXT, -- 'HIGH', 'MEDIUM', 'LOW'
    risk_score FLOAT,
    is_phishing BOOLEAN,
    confidence FLOAT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create index for faster queries
CREATE INDEX IF NOT EXISTS idx_analysis_history_user_id ON analysis_history(user_id);
CREATE INDEX IF NOT EXISTS idx_analysis_history_created_at ON analysis_history(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_analysis_history_analysis_type ON analysis_history(analysis_type);
CREATE INDEX IF NOT EXISTS idx_analysis_history_is_phishing ON analysis_history(is_phishing);

-- User Profiles Table (references organizations, so must come after)
CREATE TABLE IF NOT EXISTS user_profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    email TEXT,
    full_name TEXT,
    organization_id UUID REFERENCES organizations(id),
    role TEXT DEFAULT 'user', -- 'admin', 'user', 'viewer'
    preferences JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Threat Rules (Whitelist/Blacklist)
CREATE TABLE IF NOT EXISTS threat_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    rule_type TEXT NOT NULL, -- 'whitelist', 'blacklist'
    rule_category TEXT NOT NULL, -- 'url', 'domain', 'ip', 'email', 'keyword'
    rule_value TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by UUID REFERENCES auth.users(id)
);

CREATE INDEX IF NOT EXISTS idx_threat_rules_user_id ON threat_rules(user_id);
CREATE INDEX IF NOT EXISTS idx_threat_rules_org_id ON threat_rules(organization_id);

-- False Positive/Negative Reports
CREATE TABLE IF NOT EXISTS feedback_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    analysis_id UUID REFERENCES analysis_history(id) ON DELETE CASCADE,
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    feedback_type TEXT NOT NULL, -- 'false_positive', 'false_negative', 'correction'
    original_prediction TEXT,
    user_correction TEXT,
    comments TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_feedback_reports_analysis_id ON feedback_reports(analysis_id);
CREATE INDEX IF NOT EXISTS idx_feedback_reports_user_id ON feedback_reports(user_id);

-- Enable Row Level Security
ALTER TABLE analysis_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE threat_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE feedback_reports ENABLE ROW LEVEL SECURITY;

-- RLS Policies for analysis_history
CREATE POLICY "Users can view their own analysis history"
    ON analysis_history FOR SELECT
    USING (auth.uid() = user_id);

CREATE POLICY "Users can insert their own analysis history"
    ON analysis_history FOR INSERT
    WITH CHECK (auth.uid() = user_id);

-- RLS Policies for user_profiles
CREATE POLICY "Users can view their own profile"
    ON user_profiles FOR SELECT
    USING (auth.uid() = id);

CREATE POLICY "Users can update their own profile"
    ON user_profiles FOR UPDATE
    USING (auth.uid() = id);

-- RLS Policies for threat_rules
CREATE POLICY "Users can manage their own threat rules"
    ON threat_rules FOR ALL
    USING (auth.uid() = user_id);

-- RLS Policies for feedback_reports
CREATE POLICY "Users can create feedback reports"
    ON feedback_reports FOR INSERT
    WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can view their own feedback reports"
    ON feedback_reports FOR SELECT
    USING (auth.uid() = user_id);

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Triggers for updated_at
CREATE TRIGGER update_analysis_history_updated_at BEFORE UPDATE ON analysis_history
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_user_profiles_updated_at BEFORE UPDATE ON user_profiles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_organizations_updated_at BEFORE UPDATE ON organizations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

