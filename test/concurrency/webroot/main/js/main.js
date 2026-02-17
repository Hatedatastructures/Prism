// API基础路径
const API_BASE = '';

// 格式化价格
function format_price(price) {
    return parseFloat(price).toFixed(2);
}

// 格式化数字
function format_number(num) {
    return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

// 生成占位图片
function get_placeholder_image(width, height, text) {
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}">
        <rect fill="%23f5f5f5" width="${width}" height="${height}"/>
        <text x="50%" y="50%" text-anchor="middle" dy=".3em" fill="%23999" font-size="14">${text || '暂无图片'}</text>
    </svg>`;
    return 'data:image/svg+xml,' + encodeURIComponent(svg);
}

// 加载商品列表
async function load_products(url, container_id) {
    try {
        const response = await fetch(API_BASE + url);
        if (!response.ok) {
            throw new Error('网络请求失败');
        }
        const data = await response.json();

        const container = document.getElementById(container_id);
        if (!container) return;

        if (data.items && data.items.length > 0) {
            container.innerHTML = data.items.map(product => `
                <div class="product-card" onclick="go_to_product('${product.id}')">
                    <img src="${product.image || get_placeholder_image(200, 200, product.name)}" 
                         alt="${product.name}" 
                         onerror="this.src='${get_placeholder_image(200, 200, product.name)}'">
                    <div class="product-info">
                        <div class="product-name">${product.name}</div>
                        <div class="product-price">
                            <span class="current-price">¥${format_price(product.price)}</span>
                            ${product.original_price ? `<span class="original-price">¥${format_price(product.original_price)}</span>` : ''}
                        </div>
                        <div class="product-sales">已售 ${format_number(product.sales || 0)}</div>
                    </div>
                </div>
            `).join('');
        } else {
            container.innerHTML = '<div class="empty-state">暂无商品</div>';
        }
    } catch (error) {
        console.error('加载商品失败:', error);
        const container = document.getElementById(container_id);
        if (container) {
            container.innerHTML = '<div class="error-state">加载失败，请稍后重试</div>';
        }
    }
}

// 跳转到商品详情
function go_to_product(product_id) {
    window.location.href = `/product-detail.html?id=${product_id}`;
}

// 搜索处理
function handle_search() {
    const keyword = document.getElementById('searchInput').value.trim();
    if (keyword) {
        window.location.href = `/products?search=${encodeURIComponent(keyword)}`;
    }
}

// 回车搜索
document.addEventListener('DOMContentLoaded', function () {
    const searchInput = document.getElementById('searchInput');
    if (searchInput) {
        searchInput.addEventListener('keypress', function (e) {
            if (e.key === 'Enter') {
                handle_search();
            }
        });
    }
});

// 更新购物车数量
async function update_cart_count() {
    try {
        const response = await fetch(API_BASE + '/api/cart');
        if (!response.ok) return;

        const data = await response.json();
        const count_el = document.getElementById('cartCount');
        if (count_el) {
            count_el.textContent = data.items ? data.items.length : 0;
        }
    } catch (error) {
        console.error('获取购物车失败:', error);
    }
}

// 添加到购物车
async function add_to_cart(product_id, quantity = 1) {
    try {
        const response = await fetch(API_BASE + '/api/cart', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ product_id: product_id, quantity: quantity })
        });

        if (response.ok) {
            alert('已添加到购物车');
            update_cart_count();
            return true;
        } else {
            const error_data = await response.json();
            alert(error_data.error || '添加失败');
            return false;
        }
    } catch (error) {
        console.error('添加购物车失败:', error);
        alert('添加失败，请稍后重试');
        return false;
    }
}

// 从商品详情页添加到购物车
function add_to_cart_from_detail() {
    const url_params = new URLSearchParams(window.location.search);
    const product_id = url_params.get('id');
    const quantity = parseInt(document.getElementById('quantity').value) || 1;

    if (product_id) {
        add_to_cart(product_id, quantity);
    }
}

// 加载商品详情
async function load_product_detail(product_id) {
    try {
        const response = await fetch(API_BASE + `/api/product/${product_id}`);
        if (!response.ok) {
            throw new Error('商品不存在');
        }

        const product = await response.json();

        document.getElementById('productTitle').textContent = product.name;
        document.getElementById('productName').textContent = product.name;
        document.getElementById('productSubtitle').textContent = product.description || '';
        document.getElementById('currentPrice').textContent = format_price(product.price);
        document.getElementById('originalPrice').textContent = format_price(product.original_price || product.price);
        document.getElementById('salesCount').textContent = format_number(product.sales || 0);
        document.getElementById('stockCount').textContent = product.stock || 0;
        document.getElementById('rating').textContent = (product.rating || 0).toFixed(1);

        if (product.image) {
            const img_el = document.getElementById('mainImage');
            img_el.src = product.image;
            img_el.onerror = function () {
                this.src = get_placeholder_image(400, 400, product.name);
            };
        }

        document.title = `${product.name} - 优品商城`;

        // 加载商品详情内容
        if (product.detail) {
            document.getElementById('detailContent').innerHTML = product.detail;
        } else {
            document.getElementById('detailContent').innerHTML = '<p>暂无详细描述</p>';
        }

        // 加载规格参数
        if (product.specs) {
            const specs_table = document.getElementById('specsTable');
            specs_table.innerHTML = product.specs.map(spec => `
                <tr>
                    <th>${spec.name}</th>
                    <td>${spec.value}</td>
                </tr>
            `).join('');
        }

        // 加载用户评价
        if (product.reviews) {
            const reviews_list = document.getElementById('reviewsList');
            reviews_list.innerHTML = product.reviews.map(review => `
                <div class="review-item">
                    <div class="review-header">
                        <span class="review-author">${review.author}</span>
                        <span class="review-rating">${'★'.repeat(review.rating)}${'☆'.repeat(5 - review.rating)}</span>
                        <span class="review-date">${review.date}</span>
                    </div>
                    <div class="review-content">${review.content}</div>
                </div>
            `).join('');
        }

    } catch (error) {
        console.error('加载商品详情失败:', error);
        document.getElementById('productTitle').textContent = '加载失败';
        alert('商品不存在或加载失败');
    }
}

// 数量增减
function decrease_qty() {
    const input = document.getElementById('quantity');
    if (input && parseInt(input.value) > 1) {
        input.value = parseInt(input.value) - 1;
    }
}

function increase_qty() {
    const input = document.getElementById('quantity');
    const stock_el = document.getElementById('stockCount');
    if (input && stock_el) {
        const stock = parseInt(stock_el.textContent);
        const current_qty = parseInt(input.value);
        if (current_qty < stock) {
            input.value = current_qty + 1;
        } else {
            alert('库存不足');
        }
    }
}

// 立即购买
function buy_now() {
    const url_params = new URLSearchParams(window.location.search);
    const product_id = url_params.get('id');
    const quantity = document.getElementById('quantity').value;
    window.location.href = `/checkout.html?product_id=${product_id}&quantity=${quantity}`;
}

// 切换标签页
function switch_tab(tab_name) {
    // 更新按钮状态
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
        if (btn.dataset.tab === tab_name) {
            btn.classList.add('active');
        }
    });

    // 更新面板显示
    document.querySelectorAll('.tab-panel').forEach(panel => {
        panel.classList.remove('active');
    });

    const active_panel = document.getElementById(tab_name);
    if (active_panel) {
        active_panel.classList.add('active');
    }
}

// 显示加载状态
function show_loading(container_id) {
    const container = document.getElementById(container_id);
    if (container) {
        container.innerHTML = '<div class="loading">加载中...</div>';
    }
}

// 显示错误状态
function show_error(container_id, message) {
    const container = document.getElementById(container_id);
    if (container) {
        container.innerHTML = `<div class="error-state">${message || '加载失败，请稍后重试'}</div>`;
    }
}

// 显示空状态
function show_empty(container_id, message) {
    const container = document.getElementById(container_id);
    if (container) {
        container.innerHTML = `<div class="empty-state">${message || '暂无数据'}</div>`;
    }
}

// 防抖函数
function debounce(func, wait) {
    let timeout;
    return function executed_function(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// 节流函数
function throttle(func, limit) {
    let in_throttle;
    return function (...args) {
        if (!in_throttle) {
            func.apply(this, args);
            in_throttle = true;
            setTimeout(() => in_throttle = false, limit);
        }
    };
}

// 本地存储封装
const storage = {
    get: function (key) {
        try {
            const item = localStorage.getItem(key);
            return item ? JSON.parse(item) : null;
        } catch (error) {
            console.error('读取本地存储失败:', error);
            return null;
        }
    },
    set: function (key, value) {
        try {
            localStorage.setItem(key, JSON.stringify(value));
            return true;
        } catch (error) {
            console.error('写入本地存储失败:', error);
            return false;
        }
    },
    remove: function (key) {
        try {
            localStorage.removeItem(key);
            return true;
        } catch (error) {
            console.error('删除本地存储失败:', error);
            return false;
        }
    }
};

// 获取用户信息
function get_user_info() {
    return storage.get('user_info');
}

// 保存用户信息
function save_user_info(user_info) {
    return storage.set('user_info', user_info);
}

// 清除用户信息
function clear_user_info() {
    storage.remove('user_info');
}

// 检查登录状态
function is_logged_in() {
    return !!get_user_info();
}

// 获取token
function get_token() {
    return storage.get('token');
}

// 保存token
function save_token(token) {
    return storage.set('token', token);
}

// 清除token
function clear_token() {
    storage.remove('token');
}

// 退出登录
function logout() {
    clear_user_info();
    clear_token();
    window.location.href = '/login.html';
}

// 日期格式化
function format_date(date, format = 'YYYY-MM-DD HH:mm:ss') {
    if (!date) return '';

    const d = new Date(date);
    const year = d.getFullYear();
    const month = String(d.getMonth() + 1).padStart(2, '0');
    const day = String(d.getDate()).padStart(2, '0');
    const hours = String(d.getHours()).padStart(2, '0');
    const minutes = String(d.getMinutes()).padStart(2, '0');
    const seconds = String(d.getSeconds()).padStart(2, '0');

    return format
        .replace('YYYY', year)
        .replace('MM', month)
        .replace('DD', day)
        .replace('HH', hours)
        .replace('mm', minutes)
        .replace('ss', seconds);
}

// 相对时间
function relative_time(date) {
    if (!date) return '';

    const now = new Date();
    const target = new Date(date);
    const diff = now - target;
    const seconds = Math.floor(diff / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);

    if (seconds < 60) return '刚刚';
    if (minutes < 60) return `${minutes}分钟前`;
    if (hours < 24) return `${hours}小时前`;
    if (days < 30) return `${days}天前`;

    return format_date(date, 'YYYY-MM-DD');
}

// 页面加载完成后更新购物车
document.addEventListener('DOMContentLoaded', function () {
    update_cart_count();
});
