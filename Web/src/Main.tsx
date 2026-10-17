import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App/App';
import '@fontsource-variable/noto-sans-sc';

/** @brief 绑定管理页面唯一入口；缺失实际挂载点时明确终止初始化。 */
const Root = document.getElementById('root');
if (Root === null) throw new Error('管理页面缺少挂载点');
createRoot(Root).render(<StrictMode><App /></StrictMode>);
