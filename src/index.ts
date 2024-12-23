#!/usr/bin/env node
/**
 * Folderr MCP Server
 * 
 * This server provides tools to interact with Folderr's API, specifically for managing
 * and communicating with Folderr Assistants. It supports both token-based authentication
 * and direct API key usage.
 * 
 * @module folderr-server
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';
import axios from 'axios';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CONFIG_FILE = path.join(__dirname, '../config.json');

/**
 * Configuration interface for the Folderr MCP Server
 */
interface Config {
  /** Base URL for the Folderr API */
  baseUrl: string;
  /** Authentication token (from login or API key) */
  token?: string;
}

/**
 * Response interface for authentication requests
 */
interface AuthResponse {
  /** JWT token for authentication */
  token: string;
  /** User information */
  user: {
    /** User's unique identifier */
    id: string;
    /** User's email address */
    email: string;
  };
}

class FolderrServer {
  private server: Server;
  private config: Config;
  private axiosInstance;

  constructor() {
    this.server = new Server(
      {
        name: 'folderr-server',
        version: '0.1.0',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    // Load or initialize config
    this.config = this.loadConfig();

    this.axiosInstance = axios.create({
      baseURL: this.config.baseUrl || 'https://api-staging.folderr.com',
      headers: this.config.token ? { Authorization: `Bearer ${this.config.token}` } : {},
    });

    this.setupToolHandlers();
    
    // Error handling
    this.server.onerror = (error) => console.error('[MCP Error]', error);
    process.on('SIGINT', async () => {
      await this.server.close();
      process.exit(0);
    });
  }

  private loadConfig(): Config {
    try {
      if (fs.existsSync(CONFIG_FILE)) {
        return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf-8'));
      }
    } catch (error) {
      console.error('Error loading config:', error);
    }
    return { baseUrl: 'https://api-staging.folderr.com' };
  }

  private saveConfig() {
    try {
      fs.writeFileSync(CONFIG_FILE, JSON.stringify(this.config, null, 2));
    } catch (error) {
      console.error('Error saving config:', error);
    }
  }

  private setupToolHandlers() {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        {
          name: 'set_api_token',
          description: 'Set an API token for authentication (alternative to login)',
          inputSchema: {
            type: 'object',
            properties: {
              token: {
                type: 'string',
                description: 'API token generated from Folderr developers section',
              },
            },
            required: ['token'],
          },
        },
        {
          name: 'login',
          description: 'Login to Folderr with email and password',
          inputSchema: {
            type: 'object',
            properties: {
              email: {
                type: 'string',
                description: 'User email',
              },
              password: {
                type: 'string',
                description: 'User password',
              },
            },
            required: ['email', 'password'],
          },
        },
        {
          name: 'list_assistants',
          description: 'List all available assistants',
          inputSchema: {
            type: 'object',
            properties: {},
            required: [],
          },
        },
        {
          name: 'ask_assistant',
          description: 'Ask a question to a specific assistant',
          inputSchema: {
            type: 'object',
            properties: {
              assistant_id: {
                type: 'string',
                description: 'ID of the assistant to ask',
              },
              question: {
                type: 'string',
                description: 'Question to ask the assistant',
              },
            },
            required: ['assistant_id', 'question'],
          },
        },
        {
          name: 'list_workflows',
          description: 'List all available workflows',
          inputSchema: {
            type: 'object',
            properties: {},
            required: [],
          },
        },
        {
          name: 'get_workflow_inputs',
          description: 'Get the required inputs for a workflow',
          inputSchema: {
            type: 'object',
            properties: {
              workflow_id: {
                type: 'string',
                description: 'ID of the workflow',
              },
            },
            required: ['workflow_id'],
          },
        },
        {
          name: 'execute_workflow',
          description: 'Execute a workflow with the required inputs',
          inputSchema: {
            type: 'object',
            properties: {
              workflow_id: {
                type: 'string',
                description: 'ID of the workflow',
              },
              inputs: {
                type: 'object',
                description: 'Input values required by the workflow',
                additionalProperties: true,
              },
            },
            required: ['workflow_id', 'inputs'],
          },
        },
      ],
    }));

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      switch (request.params.name) {
        case 'login':
          return await this.handleLogin(request.params.arguments);
        case 'set_api_token':
          return await this.handleSetApiToken(request.params.arguments);
        case 'list_assistants':
          return await this.handleListAssistants();
        case 'ask_assistant':
          return await this.handleAskAssistant(request.params.arguments);
        case 'list_workflows':
          return await this.handleListWorkflows();
        case 'get_workflow_inputs':
          return await this.handleGetWorkflowInputs(request.params.arguments);
        case 'execute_workflow':
          return await this.handleExecuteWorkflow(request.params.arguments);
        default:
          throw new McpError(
            ErrorCode.MethodNotFound,
            `Unknown tool: ${request.params.name}`
          );
      }
    });
  }

  /**
   * Handle login requests using email and password
   * @param args Login arguments containing email and password
   */
  private async handleLogin(args: any) {
    try {
      const response = await this.axiosInstance.post<AuthResponse>('/api/auth/sign-in', {
        email: args.email,
        password: args.password,
      });

      // Update config and axios instance with new token
      this.config.token = response.data.token;
      this.axiosInstance.defaults.headers.common['Authorization'] = `Bearer ${this.config.token}`;
      this.saveConfig();

      return {
        content: [
          {
            type: 'text',
            text: 'Successfully logged in',
          },
        ],
      };
    } catch (error: any) {
      return {
        content: [
          {
            type: 'text',
            text: `Login failed: ${error.response?.data?.message || error.message}`,
          },
        ],
        isError: true,
      };
    }
  }

  /**
   * Handle setting an API token for authentication
   * @param args Arguments containing the API token
   */
  private async handleSetApiToken(args: any) {
    try {
      // Update config and axios instance with new token
      this.config.token = args.token;
      this.axiosInstance.defaults.headers.common['Authorization'] = `Bearer ${this.config.token}`;
      this.saveConfig();

      return {
        content: [
          {
            type: 'text',
            text: 'Successfully set API token',
          },
        ],
      };
    } catch (error: any) {
      return {
        content: [
          {
            type: 'text',
            text: `Failed to set API token: ${error.message}`,
          },
        ],
        isError: true,
      };
    }
  }

  /**
   * Handle requests to list all available assistants
   */
  private async handleListAssistants() {
    if (!this.config.token) {
      throw new McpError(ErrorCode.InvalidRequest, 'Not logged in');
    }

    try {
      const response = await this.axiosInstance.get('/api/agent');
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(response.data, null, 2),
          },
        ],
      };
    } catch (error: any) {
      return {
        content: [
          {
            type: 'text',
            text: `Failed to list assistants: ${error.response?.data?.message || error.message}`,
          },
        ],
        isError: true,
      };
    }
  }

  /**
   * Handle requests to ask questions to specific assistants
   * @param args Arguments containing assistant_id and question
   */
  private async handleAskAssistant(args: any) {
    if (!this.config.token) {
      throw new McpError(ErrorCode.InvalidRequest, 'Not logged in');
    }

    try {
      const response = await this.axiosInstance.post(
        `/api/agent/${args.assistant_id}/message`,
        { message: args.question }
      );
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(response.data, null, 2),
          },
        ],
      };
    } catch (error: any) {
      return {
        content: [
          {
            type: 'text',
            text: `Failed to ask assistant: ${error.response?.data?.message || error.message}`,
          },
        ],
        isError: true,
      };
    }
  }

  /**
   * Handle requests to list all available workflows
   */
  private async handleListWorkflows() {
    if (!this.config.token) {
      throw new McpError(ErrorCode.InvalidRequest, 'Not logged in');
    }

    try {
      const response = await this.axiosInstance.get('/api/workflows');
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(response.data, null, 2),
          },
        ],
      };
    } catch (error: any) {
      return {
        content: [
          {
            type: 'text',
            text: `Failed to list workflows: ${error.response?.data?.message || error.message}`,
          },
        ],
        isError: true,
      };
    }
  }

  /**
   * Handle requests to get workflow inputs
   * @param args Arguments containing workflow_id
   */
  private async handleGetWorkflowInputs(args: any) {
    if (!this.config.token) {
      throw new McpError(ErrorCode.InvalidRequest, 'Not logged in');
    }

    try {
      const response = await this.axiosInstance.get(`/api/workflows/api-client/${args.workflow_id}/inputs`);
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(response.data, null, 2),
          },
        ],
      };
    } catch (error: any) {
      return {
        content: [
          {
            type: 'text',
            text: `Failed to get workflow inputs: ${error.response?.data?.message || error.message}`,
          },
        ],
        isError: true,
      };
    }
  }

  /**
   * Handle requests to execute a workflow
   * @param args Arguments containing workflow_id and inputs
   */
  private async handleExecuteWorkflow(args: any) {
    if (!this.config.token) {
      throw new McpError(ErrorCode.InvalidRequest, 'Not logged in');
    }

    try {
      const response = await this.axiosInstance.post(
        `/api/workflows/api-client/${args.workflow_id}`,
        args.inputs
      );
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(response.data, null, 2),
          },
        ],
      };
    } catch (error: any) {
      return {
        content: [
          {
            type: 'text',
            text: `Failed to execute workflow: ${error.response?.data?.message || error.message}`,
          },
        ],
        isError: true,
      };
    }
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('Folderr MCP server running on stdio');
  }
}

const server = new FolderrServer();
server.run().catch(console.error);
