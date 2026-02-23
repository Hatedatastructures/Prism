// 用户中心脚本

let current_tab = 'orders';

// 初始化用户中心页
if (document.querySelector('.user-center-page')) {
    document.addEventListener('DOMContentLoaded', function () {
        init_user_center();
    });
}

// 初始化登录页
if (document.querySelector('.auth-container') && document.querySelector('#loginForm')) {
    document.addEventListener('DOMContentLoaded', function () {
        init_login_page();
    });
}

// 初始化注册页
if (document.querySelector('.auth-container') && document.querySelector('#registerForm')) {
    document.addEventListener('DOMContentLoaded', function () {
        init_register_page();
    });
}

// 初始化用户中心
function init_user_center() {
    // 解析URL参数确定当前标签
    const url_params = new URLSearchParams(window.location.search);
    current_tab = url_params.get('tab') || 'orders';

    // 更新导航高亮
    update_user_nav();

    // 显示对应的内容区域
    show_user_section(current_tab);

    // 加载对应的数据
    load_user_data(current_tab);

    // 设置导航点击事件
    setup_user_nav_events();
}

// 更新用户导航高亮
function update_user_nav() {
    const nav_items = document.querySelectorAll('.user-nav .nav-item');

    nav_items.forEach(item => {
        const href = item.getAttribute('href');
        if (href && href.includes(`tab=${current_tab}`)) {
            item.classList.add('active');
        } else {
            item.classList.remove('active');
        }
    });
}

// 显示用户内容区域
function show_user_section(tab_name) {
    const sections = document.querySelectorAll('.user-section');

    sections.forEach(section => {
        section.classList.remove('active');
        if (section.id === `${tab_name}-section`) {
            section.classList.add('active');
        }
    });
}

// 加载用户数据
function load_user_data(tab_name) {
    switch (tab_name) {
        case 'orders':
            load_orders();
            break;
        case 'address':
            load_addresses();
            break;
        case 'profile':
            load_profile();
            break;
        case 'wishlist':
            load_wishlist();
            break;
        default:
            break;
    }
}

// 设置用户导航点击事件
function setup_user_nav_events() {
    const nav_items = document.querySelectorAll('.user-nav .nav-item');

    nav_items.forEach(item => {
        item.addEventListener('click', function (e) {
            const href = this.getAttribute('href');
            if (href && href.includes('tab=')) {
                const match = href.match(/tab=([^&]+)/);
                if (match) {
                    current_tab = match[1];
                    update_user_nav();
                    show_user_section(current_tab);
                    load_user_data(current_tab);
                }
            }
        });
    });
}

// 加载订单列表
async function load_orders(status = 'all') {
    const container = document.getElementById('orderList');
    if (!container) return;

    try {
        const response = await fetch(`/api/orders?status=${status}`);
        if (!response.ok) {
            throw new Error('加载失败');
        }

        const data = await response.json();

        if (!data.orders || data.orders.length === 0) {
            container.innerHTML = `
                <div class="empty-orders">
                    <div class="empty-icon">📦</div>
                    <p>暂无订单</p>
                    <a href="/products" class="btn-shop">去购物</a>
                </div>
            `;
            return;
        }

        container.innerHTML = data.orders.map(order => `
            <div class="order-item">
                <div class="order-header">
                    <span class="order-number">订单号: ${order.order_number}</span>
                    <span class="order-status ${order.status}">${get_order_status_text(order.status)}</span>
                </div>
                <div class="order-body">
                    <div class="order-products">
                        ${order.items.map(item => `
                            <div class="order-product">
                                <img src="${item.image || get_placeholder_image(60, 60, item.name)}" 
                                     alt="${item.name}"
                                     onerror="this.src='${get_placeholder_image(60, 60, item.name)}'">
                                <div class="order-product-info">
                                    <div class="order-product-name">${item.name}</div>
                                    <div class="order-product-spec">${item.spec || ''}</div>
                                </div>
                                <div class="order-product-quantity">x${item.quantity}</div>
                                <div class="order-product-price">¥${format_price(item.price * item.quantity)}</div>
                            </div>
                        `).join('')}
                    </div>
                </div>
                <div class="order-footer">
                    <div class="order-total">
                        合计: <span>¥${format_price(order.total)}</span>
                    </div>
                    <div class="order-actions">
                        ${get_order_actions(order.status, order.id)}
                    </div>
                </div>
            </div>
        `).join('');

    } catch (error) {
        console.error('加载订单失败:', error);
        container.innerHTML = `
            <div class="error-state" style="text-align: center; padding: 40px;">
                加载失败，请稍后重试
            </div>
        `;
    }
}

// 获取订单状态文本
function get_order_status_text(status) {
    const status_map = {
        'pending': '待付款',
        'paid': '已付款',
        'shipped': '已发货',
        'completed': '已完成',
        'cancelled': '已取消'
    };
    return status_map[status] || status;
}

// 获取订单操作按钮
function get_order_actions(status, order_id) {
    switch (status) {
        case 'pending':
            return `
                <button onclick="cancel_order('${order_id}')">取消订单</button>
                <button class="primary" onclick="pay_order('${order_id}')">立即付款</button>
            `;
        case 'shipped':
            return `
                <button onclick="view_logistics('${order_id}')">查看物流</button>
                <button class="primary" onclick="confirm_receipt('${order_id}')">确认收货</button>
            `;
        case 'completed':
            return `
                <button onclick="delete_order('${order_id}')">删除订单</button>
                <button class="primary" onclick="buy_again('${order_id}')">再次购买</button>
            `;
        default:
            return `
                <button onclick="view_order('${order_id}')">查看详情</button>
            `;
    }
}

// 加载收货地址
async function load_addresses() {
    // 模拟数据
    const addresses = [
        {
            id: '1',
            name: '张三',
            phone: '138****8888',
            address: '北京市朝阳区建国路88号',
            is_default: true
        },
        {
            id: '2',
            name: '李四',
            phone: '139****6666',
            address: '上海市浦东新区陆家嘴环路1000号',
            is_default: false
        }
    ];

    const container = document.querySelector('.address-list');
    if (!container) return;

    container.innerHTML = addresses.map(addr => `
        <div class="address-item ${addr.is_default ? 'active' : ''}">
            <div class="address-header">
                <span class="name">${addr.name}</span>
                <span class="phone">${addr.phone}</span>
                ${addr.is_default ? '<span class="default-tag">默认</span>' : ''}
            </div>
            <div class="address-detail">${addr.address}</div>
            <div class="address-actions">
                <button class="btn-edit" onclick="edit_address('${addr.id}')">编辑</button>
                <button class="btn-delete" onclick="delete_address('${addr.id}')">删除</button>
            </div>
        </div>
    `).join('');
}

// 加载个人信息
async function load_profile() {
    // 模拟数据
    const user_info = {
        username: 'user123',
        nickname: '用户昵称',
        email: 'user@example.com',
        phone: '138****8888',
        gender: 'male'
    };

    const form = document.querySelector('.profile-form');
    if (!form) return;

    const nickname_input = form.querySelector('input[value*="用户昵称"]');
    const email_input = form.querySelector('input[type="email"]');
    const phone_input = form.querySelector('input[type="tel"]');
    const gender_select = form.querySelector('select');

    if (nickname_input) nickname_input.value = user_info.nickname;
    if (email_input) email_input.value = user_info.email;
    if (phone_input) phone_input.value = user_info.phone;
    if (gender_select) gender_select.value = user_info.gender;
}

// 加载收藏列表
async function load_wishlist() {
    // 模拟数据
    const products = [];

    const container = document.getElementById('wishlistList');
    if (!container) return;

    if (products.length === 0) {
        container.innerHTML = `
            <div class="empty-wishlist">
                <div class="empty-icon">❤️</div>
                <p>暂无收藏商品</p>
                <a href="/products" class="btn-shop">去逛逛</a>
            </div>
        `;
        return;
    }

    container.innerHTML = `<div class="wishlist-grid">
        ${products.map(product => `
            <div class="wishlist-item">
                <img src="${product.image || get_placeholder_image(180, 180, product.name)}" 
                     alt="${product.name}"
                     onerror="this.src='${get_placeholder_image(180, 180, product.name)}'">
                <div class="wishlist-item-info">
                    <div class="wishlist-item-name">${product.name}</div>
                    <div class="wishlist-item-price">¥${format_price(product.price)}</div>
                </div>
                <div class="wishlist-item-actions">
                    <button onclick="remove_from_wishlist('${product.id}')">取消收藏</button>
                    <button onclick="add_to_cart('${product.id}')">加入购物车</button>
                </div>
            </div>
        `).join('')}
    </div>`;
}

// 初始化登录页
function init_login_page() {
    const form = document.getElementById('loginForm');
    if (!form) return;

    form.addEventListener('submit', handle_login);
}

// 处理登录
async function handle_login(event) {
    event.preventDefault();

    const form = event.target;
    const username = form.querySelector('#username').value;
    const password = form.querySelector('#password').value;
    const remember_me = form.querySelector('#rememberMe').checked;

    try {
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username: username,
                password: password,
                remember_me: remember_me
            })
        });

        if (response.ok) {
            const data = await response.json();
            save_token(data.token);
            save_user_info(data.user);
            alert('登录成功！');
            window.location.href = '/';
        } else {
            const error_data = await response.json();
            alert(error_data.error || '登录失败，请检查用户名和密码');
        }
    } catch (error) {
        console.error('登录失败:', error);
        alert('登录失败，请稍后重试');
    }
}

// 初始化注册页
function init_register_page() {
    const form = document.getElementById('registerForm');
    if (!form) return;

    form.addEventListener('submit', handle_register);
}

// 处理注册
async function handle_register(event) {
    event.preventDefault();

    const form = event.target;
    const username = form.querySelector('#username').value;
    const phone = form.querySelector('#phone').value;
    const email = form.querySelector('#email').value;
    const password = form.querySelector('#password').value;
    const confirm_password = form.querySelector('#confirmPassword').value;
    const captcha = form.querySelector('#captcha').value;
    const agreement = form.querySelector('#agreement').checked;

    // 验证
    if (password !== confirm_password) {
        alert('两次输入的密码不一致');
        return;
    }

    if (!agreement) {
        alert('请阅读并同意用户协议和隐私政策');
        return;
    }

    try {
        const response = await fetch('/api/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username: username,
                phone: phone,
                email: email,
                password: password,
                captcha: captcha
            })
        });

        if (response.ok) {
            alert('注册成功！请登录');
            window.location.href = '/login.html';
        } else {
            const error_data = await response.json();
            alert(error_data.error || '注册失败');
        }
    } catch (error) {
        console.error('注册失败:', error);
        alert('注册失败，请稍后重试');
    }
}

// 发送验证码
async function send_captcha() {
    const phone_input = document.querySelector('#phone');
    if (!phone_input) return;

    const phone = phone_input.value;
    if (!phone || !/^1[3-9]\d{9}$/.test(phone)) {
        alert('请输入正确的手机号');
        return;
    }

    const button = document.querySelector('.btn-captcha');
    if (!button) return;

    try {
        const response = await fetch('/api/captcha/send', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ phone: phone })
        });

        if (response.ok) {
            alert('验证码已发送');
            start_countdown(button);
        } else {
            const error_data = await response.json();
            alert(error_data.error || '发送失败');
        }
    } catch (error) {
        console.error('发送验证码失败:', error);
        alert('发送失败，请稍后重试');
    }
}

// 倒计时
function start_countdown(button) {
    let seconds = 60;
    button.disabled = true;
    button.textContent = `${seconds}秒后重新发送`;

    const timer = setInterval(() => {
        seconds--;
        button.textContent = `${seconds}秒后重新发送`;

        if (seconds <= 0) {
            clearInterval(timer);
            button.disabled = false;
            button.textContent = '获取验证码';
        }
    }, 1000);
}

// 订单操作
function cancel_order(order_id) {
    if (!confirm('确定要取消这个订单吗？')) return;
    alert('取消订单功能待实现');
}

function pay_order(order_id) {
    window.location.href = `/payment.html?order_id=${order_id}`;
}

function view_logistics(order_id) {
    alert('查看物流功能待实现');
}

function confirm_receipt(order_id) {
    if (!confirm('确定已收到商品吗？')) return;
    alert('确认收货功能待实现');
}

function delete_order(order_id) {
    if (!confirm('确定要删除这个订单吗？')) return;
    alert('删除订单功能待实现');
}

function buy_again(order_id) {
    alert('再次购买功能待实现');
}

function view_order(order_id) {
    window.location.href = `/order-detail.html?order_id=${order_id}`;
}

// 地址操作
function edit_address(address_id) {
    alert('编辑地址功能待实现');
}

function delete_address(address_id) {
    if (!confirm('确定要删除这个地址吗？')) return;
    alert('删除地址功能待实现');
}

// 收藏操作
function remove_from_wishlist(product_id) {
    if (!confirm('确定要取消收藏吗？')) return;
    alert('取消收藏功能待实现');
}

// 导出函数供HTML调用
window.handle_login = handle_login;
window.handle_register = handle_register;
window.send_captcha = send_captcha;
window.cancel_order = cancel_order;
window.pay_order = pay_order;
window.view_logistics = view_logistics;
window.confirm_receipt = confirm_receipt;
window.delete_order = delete_order;
window.buy_again = buy_again;
window.view_order = view_order;
window.edit_address = edit_address;
window.delete_address = delete_address;
window.remove_from_wishlist = remove_from_wishlist;
