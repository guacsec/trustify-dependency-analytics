import { errorReport } from './reportWithError.mock';
import { forbiddenReport } from './reportWithForbidden.mock';
import { unauthorizedReport } from './reportWithUnauthorized.mock';
import { reportBasic } from './reportBasic.mock';
import { reportWithWarning } from './reportWithWarning.mock';
import { dockerReport} from './reportDocker.mock';

export const MOCK_REPORT = {
  basic: reportBasic,
  error: errorReport,
  forbidden: forbiddenReport,
  unauthorizedReport: unauthorizedReport,
  docker: dockerReport,
  warning: reportWithWarning,
};
