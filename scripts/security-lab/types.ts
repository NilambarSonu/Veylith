export interface LabCase {
  id: string;
  scenarioId: string;
  scenarioName: string;
  tier: string;
  split: string;
  category: string;
  stage: string;
  context: Record<string, string>;
  operation: string;
  input: string | string[];
  expectedSecurityDecision: 'allow' | 'block';
  expectedEnforcementOutcome: 'deliver' | 'contain';
  groundTruth: string;
  aiInferenceShouldBeInvoked: boolean;
  testModes: string[];
  safetyConstraints: string[];
}
export interface Observation {
  id: string;
  scenarioId: string;
  tier: string;
  category: string;
  expected: string;
  predicted: 'allow' | 'block' | null;
  contained: boolean;
  delivered: boolean;
  enforcementSuccess: boolean;
  forwardedCalls: number;
  forwardingViolation: boolean;
  isolationFailures: number;
  inferenceCalls: number;
  latencyMs: number;
  unsupported?: string;
  error?: string;
  evidence: unknown;
}
