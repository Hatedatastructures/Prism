// 商品列表页脚本

let current_page = 1;
let page_size = 20;
let total_count = 0;
let current_sort = 'default';
let current_category = 'all';
let min_price = null;
let max_price = null;
let search_keyword = '';

// 初始化
document.addEventListener('DOMContentLoaded', function () {
    parse_url_params();
    load_products_page();
    setup_event_listeners();
});

// 解析URL参数
function parse_url_params() {
    const url_params = new URLSearchParams(window.location.search);

    current_page = parseInt(url_params.get('page')) || 1;
    page_size = parseInt(url_params.get('page_size')) || 20;
    current_sort = url_params.get('sort') || 'default';
    current_category = url_params.get('category') || 'all';
    min_price = url_params.get('min_price');
    max_price = url_params.get('max_price');
    search_keyword = url_params.get('search') || '';

    // 更新价格输入框
    if (min_price) {
        const min_input = document.getElementById('minPrice');
        if (min_input) min_input.value = min_price;
    }
    if (max_price) {
        const max_input = document.getElementById('maxPrice');
        if (max_input) max_input.value = max_price;
    }

    // 更新分类高亮
    update_category_active();
    update_sort_active();
}

// 更新分类高亮
function update_category_active() {
    const category_links = document.querySelectorAll('.filter-list a');
    category_links.forEach(link => {
        const link_category = link.href.match(/category=([^&]+)/);
        if (link_category && link_category[1] === current_category) {
            link.classList.add('active');
        } else if (!link_category && current_category === 'all') {
            link.classList.add('active');
        } else {
            link.classList.remove('active');
        }
    });
}

// 更新排序高亮
function update_sort_active() {
    const sort_buttons = document.querySelectorAll('.sort-btn');
    sort_buttons.forEach(btn => {
        if (btn.dataset.sort === current_sort) {
            btn.classList.add('active');
        } else {
            btn.classList.remove('active');
        }
    });
}

// 加载商品列表
async function load_products_page() {
    show_loading('productGrid');

    try {
        let url = `/api/products?page=${current_page}&page_size=${page_size}`;

        if (current_category !== 'all') {
            url += `&category=${current_category}`;
        }

        if (current_sort !== 'default') {
            url += `&sort=${current_sort}`;
        }

        if (min_price) {
            url += `&min_price=${min_price}`;
        }

        if (max_price) {
            url += `&max_price=${max_price}`;
        }

        if (search_keyword) {
            url += `&search=${encodeURIComponent(search_keyword)}`;
        }

        const response = await fetch(url);
        if (!response.ok) {
            throw new Error('加载失败');
        }

        const data = await response.json();
        total_count = data.total || 0;

        render_products(data.items || []);
        render_pagination();
        update_total_count();

    } catch (error) {
        console.error('加载商品失败:', error);
        show_error('productGrid', '加载失败，请稍后重试');
    }
}

// 渲染商品列表
function render_products(products) {
    const container = document.getElementById('productGrid');
    if (!container) return;

    if (products.length === 0) {
        container.innerHTML = `
            <div class="empty-products" style="grid-column: 1/-1; text-align: center; padding: 60px 20px;">
                <div class="empty-icon" style="font-size: 80px; margin-bottom: 20px;">📦</div>
                <p style="font-size: 18px; color: #666; margin-bottom: 30px;">暂无商品</p>
                <a href="/products" style="display: inline-block; background: #e74c3c; color: #fff; padding: 12px 30px; border-radius: 5px;">浏览全部商品</a>
            </div>
        `;
        return;
    }

    container.innerHTML = products.map(product => `
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
}

// 渲染分页
function render_pagination() {
    const container = document.getElementById('pagination');
    if (!container) return;

    const total_pages = Math.ceil(total_count / page_size);

    if (total_pages <= 1) {
        container.innerHTML = '';
        return;
    }

    let html = '';

    // 上一页
    html += `<button ${current_page === 1 ? 'disabled' : ''} onclick="go_to_page(${current_page - 1})">&lt;</button>`;

    // 页码
    const start_page = Math.max(1, current_page - 2);
    const end_page = Math.min(total_pages, current_page + 2);

    if (start_page > 1) {
        html += `<button onclick="go_to_page(1)">1</button>`;
        if (start_page > 2) {
            html += `<span class="page-ellipsis">...</span>`;
        }
    }

    for (let i = start_page; i <= end_page; i++) {
        html += `<button class="${i === current_page ? 'active' : ''}" onclick="go_to_page(${i})">${i}</button>`;
    }

    if (end_page < total_pages) {
        if (end_page < total_pages - 1) {
            html += `<span class="page-ellipsis">...</span>`;
        }
        html += `<button onclick="go_to_page(${total_pages})">${total_pages}</button>`;
    }

    // 下一页
    html += `<button ${current_page === total_pages ? 'disabled' : ''} onclick="go_to_page(${current_page + 1})">&gt;</button>`;

    // 页码信息
    html += `<span class="page-info">第 ${current_page} / ${total_pages} 页</span>`;

    container.innerHTML = html;
}

// 更新总数
function update_total_count() {
    const count_el = document.getElementById('totalCount');
    if (count_el) {
        count_el.textContent = format_number(total_count);
    }
}

// 跳转页码
function go_to_page(page) {
    if (page < 1 || page > Math.ceil(total_count / page_size)) return;

    current_page = page;
    update_url();
    load_products_page();
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

// 切换排序
function change_sort(sort) {
    current_sort = sort;
    current_page = 1;
    update_sort_active();
    update_url();
    load_products_page();
}

// 应用价格筛选
function apply_price_filter() {
    const min_input = document.getElementById('minPrice');
    const max_input = document.getElementById('maxPrice');

    min_price = min_input ? min_input.value : null;
    max_price = max_input ? max_input.value : null;

    // 验证价格范围
    if (min_price && max_price && parseFloat(min_price) > parseFloat(max_price)) {
        alert('最低价不能高于最高价');
        return;
    }

    current_page = 1;
    update_url();
    load_products_page();
}

// 更新URL
function update_url() {
    const url_params = new URLSearchParams();

    if (current_page > 1) {
        url_params.set('page', current_page);
    }

    if (page_size !== 20) {
        url_params.set('page_size', page_size);
    }

    if (current_sort !== 'default') {
        url_params.set('sort', current_sort);
    }

    if (current_category !== 'all') {
        url_params.set('category', current_category);
    }

    if (min_price) {
        url_params.set('min_price', min_price);
    }

    if (max_price) {
        url_params.set('max_price', max_price);
    }

    if (search_keyword) {
        url_params.set('search', search_keyword);
    }

    const query_string = url_params.toString();
    const new_url = query_string ? `?${query_string}` : window.location.pathname;

    window.history.replaceState({}, '', new_url);
}

// 设置事件监听器
function setup_event_listeners() {
    // 价格输入框回车
    const min_input = document.getElementById('minPrice');
    const max_input = document.getElementById('maxPrice');

    if (min_input) {
        min_input.addEventListener('keypress', function (e) {
            if (e.key === 'Enter') {
                apply_price_filter();
            }
        });
    }

    if (max_input) {
        max_input.addEventListener('keypress', function (e) {
            if (e.key === 'Enter') {
                apply_price_filter();
            }
        });
    }

    // 搜索框回车
    const search_input = document.getElementById('searchInput');
    if (search_input && search_keyword) {
        search_input.value = search_keyword;
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
        container.innerHTML = `<div class="error-state" style="grid-column: 1/-1; text-align: center; padding: 40px;">${message || '加载失败，请稍后重试'}</div>`;
    }
}

// 显示空状态
function show_empty(container_id, message) {
    const container = document.getElementById(container_id);
    if (container) {
        container.innerHTML = `<div class="empty-state" style="grid-column: 1/-1; text-align: center; padding: 40px;">${message || '暂无数据'}</div>`;
    }
}

// 导出函数供HTML调用
window.go_to_page = go_to_page;
window.change_sort = change_sort;
window.apply_price_filter = apply_price_filter;
