--
-- PostgreSQL database dump
--

\restrict d65k8Ij7a5qd7OfbNZljvi6ssluLyzexVs3Ku3LrKgQkRgbNPxAzFFjyjMakzSy

-- Dumped from database version 16.13 (Debian 16.13-1.pgdg13+1)
-- Dumped by pg_dump version 18.3 (Debian 18.3-1.pgdg13+1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- Name: vector; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS vector WITH SCHEMA public;


--
-- Name: EXTENSION vector; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION vector IS 'vector data type and ivfflat and hnsw access methods';


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: finding_ai_analysis; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.finding_ai_analysis (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    finding_id integer NOT NULL,
    title text,
    risk_analysis text,
    exploit_explanation text,
    impact text,
    remediation text,
    secure_code_example text,
    owasp_reference text,
    attack_complexity text,
    exploitability text,
    business_risk text,
    recommended_priority text,
    risk_score numeric,
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.finding_ai_analysis OWNER TO postgres;

--
-- Name: finding_recommendations; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.finding_recommendations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    finding_id integer NOT NULL,
    content text NOT NULL,
    status text DEFAULT 'proposed'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    approved_by integer,
    approved_at timestamp with time zone,
    cvss_score numeric(4,1),
    cvss_vector text,
    ai_risk_score integer,
    confidence integer,
    false_positive_likelihood text,
    priority text,
    attack_complexity text,
    privileges_required text,
    user_interaction text,
    owasp_category text,
    code_fix_example text
);


ALTER TABLE public.finding_recommendations OWNER TO postgres;

--
-- Name: findings; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.findings (
    id integer NOT NULL,
    product_id integer,
    title text,
    description text,
    severity text,
    scanner text,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    ai_generated boolean DEFAULT false,
    solution text,
    solution_updated_at timestamp without time zone,
    url text,
    method text,
    parameter text,
    attack text,
    evidence text,
    reference text,
    cwe text,
    plugin_id text
);


ALTER TABLE public.findings OWNER TO postgres;

--
-- Name: knowledge_base; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.knowledge_base (
    id integer NOT NULL,
    source text NOT NULL,
    title text NOT NULL,
    content text NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb,
    embedding public.vector(384),
    created_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.knowledge_base OWNER TO postgres;

--
-- Name: knowledge_base_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.knowledge_base_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.knowledge_base_id_seq OWNER TO postgres;

--
-- Name: knowledge_base_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.knowledge_base_id_seq OWNED BY public.knowledge_base.id;


--
-- Name: performance_results; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.performance_results (
    id integer NOT NULL,
    product_name text NOT NULL,
    product_id integer,
    run_at timestamp without time zone DEFAULT now(),
    app_url text,
    duration_secs integer,
    vus integer,
    total_requests integer,
    failed_requests integer,
    error_rate numeric(5,2),
    avg_response_ms numeric(10,2),
    min_response_ms numeric(10,2),
    max_response_ms numeric(10,2),
    p90_response_ms numeric(10,2),
    p95_response_ms numeric(10,2),
    throughput numeric(10,2),
    status text DEFAULT 'completed'::text
);


ALTER TABLE public.performance_results OWNER TO postgres;

--
-- Name: performance_results_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.performance_results_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.performance_results_id_seq OWNER TO postgres;

--
-- Name: performance_results_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.performance_results_id_seq OWNED BY public.performance_results.id;


--
-- Name: products; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.products (
    id integer NOT NULL,
    name text NOT NULL,
    zap_report_path text,
    zap_uploaded_at timestamp with time zone
);


ALTER TABLE public.products OWNER TO postgres;

--
-- Name: users; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.users (
    id bigint NOT NULL,
    email text NOT NULL,
    password_hash text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.users OWNER TO postgres;

--
-- Name: users_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.users_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.users_id_seq OWNER TO postgres;

--
-- Name: users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;


--
-- Name: knowledge_base id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.knowledge_base ALTER COLUMN id SET DEFAULT nextval('public.knowledge_base_id_seq'::regclass);


--
-- Name: performance_results id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.performance_results ALTER COLUMN id SET DEFAULT nextval('public.performance_results_id_seq'::regclass);


--
-- Name: users id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);


--
-- Name: finding_ai_analysis finding_ai_analysis_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.finding_ai_analysis
    ADD CONSTRAINT finding_ai_analysis_pkey PRIMARY KEY (id);


--
-- Name: finding_recommendations finding_recommendations_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.finding_recommendations
    ADD CONSTRAINT finding_recommendations_pkey PRIMARY KEY (id);


--
-- Name: findings findings_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.findings
    ADD CONSTRAINT findings_pkey PRIMARY KEY (id);


--
-- Name: knowledge_base knowledge_base_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.knowledge_base
    ADD CONSTRAINT knowledge_base_pkey PRIMARY KEY (id);


--
-- Name: performance_results performance_results_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.performance_results
    ADD CONSTRAINT performance_results_pkey PRIMARY KEY (id);


--
-- Name: products products_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.products
    ADD CONSTRAINT products_pkey PRIMARY KEY (id);


--
-- Name: finding_recommendations unique_proposed_per_finding; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.finding_recommendations
    ADD CONSTRAINT unique_proposed_per_finding UNIQUE (finding_id, status);


--
-- Name: users users_email_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: knowledge_base_embedding_idx; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX knowledge_base_embedding_idx ON public.knowledge_base USING ivfflat (embedding public.vector_cosine_ops) WITH (lists='100');


--
-- Name: one_approved_rec_per_finding; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX one_approved_rec_per_finding ON public.finding_recommendations USING btree (finding_id) WHERE (status = 'approved'::text);


--
-- Name: unique_ai_analysis_per_finding; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX unique_ai_analysis_per_finding ON public.finding_ai_analysis USING btree (finding_id);


--
-- Name: finding_ai_analysis finding_ai_analysis_finding_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.finding_ai_analysis
    ADD CONSTRAINT finding_ai_analysis_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES public.findings(id) ON DELETE CASCADE;


--
-- Name: finding_recommendations finding_recommendations_approved_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.finding_recommendations
    ADD CONSTRAINT finding_recommendations_approved_by_fkey FOREIGN KEY (approved_by) REFERENCES public.users(id);


--
-- Name: finding_recommendations finding_recommendations_finding_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.finding_recommendations
    ADD CONSTRAINT finding_recommendations_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES public.findings(id) ON DELETE CASCADE;


--
-- Name: performance_results performance_results_product_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.performance_results
    ADD CONSTRAINT performance_results_product_id_fkey FOREIGN KEY (product_id) REFERENCES public.products(id);


--
-- PostgreSQL database dump complete
--

\unrestrict d65k8Ij7a5qd7OfbNZljvi6ssluLyzexVs3Ku3LrKgQkRgbNPxAzFFjyjMakzSy

