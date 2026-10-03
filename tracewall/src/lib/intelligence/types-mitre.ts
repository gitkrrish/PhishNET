// ============================================================
// PhishNet — MITRE ATT&CK Framework Type Definitions
//
// MITRE ATT&CK types for threat actor TTP mapping and analysis.
// These types extend the central intelligence model.
// ============================================================

/** MITRE ATT&CK Tactic categories */
export type MitreTactic =
  | 'RECONNAISSANCE'
  | 'RESOURCE_DEVELOPMENT'
  | 'INITIAL_ACCESS'
  | 'EXECUTION'
  | 'PERSISTENCE'
  | 'PRIVILEGE_ESCALATION'
  | 'DEFENSE_EVASION'
  | 'CREDENTIAL_ACCESS'
  | 'DISCOVERY'
  | 'LATERAL_MOVEMENT'
  | 'COLLECTION'
  | 'COMMAND_AND_CONTROL'
  | 'EXFILTRATION'
  | 'IMPACT';

/** MITRE ATT&CK Platform types */
export type MitrePlatform =
  | 'Windows'
  | 'Linux'
  | 'macOS'
  | 'Android'
  | 'iOS'
  | 'Network'
  | 'Cloud'
  | 'Containers'
  | 'Firmware'
  | 'Hardware'
  | 'ICS/SCADA'
  | 'IoT';

/** MITRE ATT&CK Data Source types */
export type MitreDataSource =
  | 'Process'
  | 'File'
  | 'Network Traffic'
  | 'Registry'
  | 'Command'
  | 'Module'
  | 'Script'
  | 'User Account'
  | 'Process Tree'
  | 'File System'
  | 'Authentication'
  | 'Cloud API'
  | 'Email'
  | 'Log';

/** MITRE ATT&CK Permission types */
export type MitrePermission =
  | 'User'
  | 'Administrator'
  | 'Root'
  | 'System'
  | 'Service'
  | 'Sudo';

/** A MITRE ATT&CK Technique or Sub-Technique */
export interface MitreTtp {
  id: string;
  /** MITRE ATT&CK ID (e.g., "T1059", "T1059.001") */
  techniqueId: string;
  /** Technique name (e.g., "Command and Scripting Interpreter") */
  name: string;
  /** Detailed description */
  description: string;
  /** Tactic category this technique belongs to */
  tactic: MitreTactic;
  /** Sub-technique ID if applicable (e.g., "001") */
  subTechniqueId?: string;
  /** Sub-technique name if applicable */
  subTechnique?: string;
  /** Platforms this technique applies to */
  platforms: MitrePlatform[];
  /** Permissions required for this technique */
  permissionsRequired: MitrePermission[];
  /** Data sources that can detect this technique */
  dataSources: MitreDataSource[];
  /** Actors known to use this TTP */
  actorIds: string[];
  /** Infrastructure IDs associated with this TTP */
  infrastructureIds: string[];
  /** Handle IDs associated with this TTP */
  handleIds: string[];
  /** Evidence IDs supporting this TTP attribution */
  evidenceIds: string[];
  /** Confidence score (0-100) for the TTP attribution */
  confidence: number;
  /** When this TTP was first observed */
  firstSeen: string;
  /** When this TTP was last observed */
  lastSeen: string;
  /** External references (URLs, MITRE IDs, etc.) */
  references: string[];
  /** Notes from analysts */
  notes?: string;
  /** Data state tracking */
  dataState?: string;
  /** Analyst who added/updated this */
  analyst?: string;
}

/** MITRE ATT&CK Matrix structure for visualization */
export interface MitreMatrixCell {
  tactic: MitreTactic;
  techniqueId: string;
  name: string;
  subTechniqueId?: string;
  actorCount: number; // Number of actors using this TTP
  confidence: number; // Average confidence across actors
  isActive: boolean; // Whether any actor uses this TTP
}

/** MITRE ATT&CK Matrix row (tactic with all techniques) */
export interface MitreMatrixRow {
  tactic: MitreTactic;
  techniques: MitreMatrixCell[];
}

/** Complete MITRE ATT&CK Matrix */
export interface MitreMatrix {
  rows: MitreMatrixRow[];
  totalTtps: number;
  totalActiveTtps: number;
  actors: string[];
}

/** Actor-specific MITRE ATT&CK profile */
export interface ActorMitreProfile {
  actorId: string;
  ttps: MitreTtp[];
  tactics: MitreTactic[];
  platforms: MitrePlatform[];
  mostUsedTactic?: MitreTactic;
  highestConfidenceTtp?: MitreTtp;
}

/** MITRE ATT&CK TTP correlation result */
export interface MitreTtpCorrelation {
  ttpId: string;
  actorIds: string[];
  sharedInfrastructure: string[];
  sharedHandles: string[];
  confidence: number;
  explanation: string;
}

/** MITRE ATT&CK search/filter options */
export interface MitreFilterOptions {
  tactics?: MitreTactic[];
  platforms?: MitrePlatform[];
  actors?: string[];
  minConfidence?: number;
  searchQuery?: string;
}
