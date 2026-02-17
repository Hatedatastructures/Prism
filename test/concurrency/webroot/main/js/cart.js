// 购物车脚本

let cart_data = null;
let selected_items = new Set();

// 初始化购物车页
if (document.querySelector('.cart-page')) {
    document.addEventListener('DOMContentLoaded', function() {
        load_cart();
    });
}

// 初始化结算页
if (document.querySelector('.checkout-page')) {
    document.addEventListener('DOMContentLoaded', function() {
        load_checkout_data();
    });
}

// 加载购物车数据
async function load_cart() {
    show_loading('cartItems');
    
    try {
        const response = await fetch('/api/cart');
        if (!response.ok) {
            throw new Error('加载失败');
        }
        
        const data = await response.json();
        cart_data = data;
        
        render_cart(data);
        update_cart_summary();

    } catch (error) {
        console.error('加载购物车失败:', error);
        show_error('cartItems', '加载失败，请稍后重试');
        toggle_cart_empty(true);
    }
}

// 渲染购物车
function render_cart(data) {
    const container = document.getElementById('cartItems');
    const empty_cart = document.getElementById('emptyCart');
    const cart_content = document.getElementById('cartContent');
    
    if (!container) return;

    if (!data.items || data.items.length === 0) {
        toggle_cart_empty(true);
        return;
    }

    toggle_cart_empty(false);

    container.innerHTML = data.items.map((item, index) => `
        <div class="cart-item" data-id="${item.id}" data-index="${index}">
            <div class="checkbox">
                <input type="checkbox" 
                       class="item-checkbox" 
                       data-id="${item.id}"
                       ${selected_items.has(item.id) ? 'checked' : ''}
                       onchange="toggle_item_select('${item.id}')">
            </div>
            <div class="col-product">
                <img src="${item.image || get_placeholder_image(80, 80, item.name)}" 
                     alt="${item.name}" 
                     class="product-image"
                     onerror="this.src='${get_placeholder_image(80, 80, item.name)}'">
                <div class="product-info">
                    <div class="product-name">${item.name}</div>
                    <div class="product-spec">${item.spec || ''}</div>
                </div>
            </div>
            <div class="col-price">¥${format_price(item.price)}</div>
            <div class="col-quantity">
                <div class="quantity-selector">
                    <button onclick="change_quantity('${item.id}', -1)">-</button>
                    <input type="number" 
                           value="${item.quantity}" 
                           min="1" 
                           max="${item.stock || 999}"
                           onchange="update_quantity('${item.id}', this.value)">
                    <button onclick="change_quantity('${item.id}', 1)">+</button>
                </div>
            </div>
            <div class="col-subtotal">¥${format_price(item.price * item.quantity)}</div>
            <div class="col-action">
                <button class="btn-delete" onclick="delete_item('${item.id}')">删除</button>
            </div>
        </div>
    `).join('');

    // 更新全选状态
    update_select_all_state();
}

// 切换购物车空状态
function toggle_cart_empty(is_empty) {
    const empty_cart = document.getElementById('emptyCart');
    const cart_content = document.getElementById('cartContent');
    
    if (empty_cart && cart_content) {
        if (is_empty) {
            empty_cart.style.display = 'block';
            cart_content.style.display = 'none';
        } else {
            empty_cart.style.display = 'none';
            cart_content.style.display = 'block';
        }
    }
}

// 切换商品选中状态
function toggle_item_select(item_id) {
    if (selected_items.has(item_id)) {
        selected_items.delete(item_id);
    } else {
        selected_items.add(item_id);
    }
    
    update_select_all_state();
    update_cart_summary();
}

// 全选/取消全选
function toggle_select_all() {
    const select_all = document.getElementById('selectAll');
    const select_all_bottom = document.getElementById('selectAllBottom');
    const is_checked = select_all ? select_all.checked : false;
    
    if (is_checked) {
        if (cart_data && cart_data.items) {
            cart_data.items.forEach(item => {
                selected_items.add(item.id);
            });
        }
    } else {
        selected_items.clear();
    }

    // 更新所有复选框
    document.querySelectorAll('.item-checkbox').forEach(checkbox => {
        checkbox.checked = is_checked;
    });

    // 同步底部全选框
    if (select_all_bottom) {
        select_all_bottom.checked = is_checked;
    }

    update_cart_summary();
}

// 更新全选状态
function update_select_all_state() {
    const select_all = document.getElementById('selectAll');
    const select_all_bottom = document.getElementById('selectAllBottom');
    
    if (!cart_data || !cart_data.items || cart_data.items.length === 0) {
        if (select_all) select_all.checked = false;
        if (select_all_bottom) select_all_bottom.checked = false;
        return;
    }

    const all_selected = cart_data.items.every(item => selected_items.has(item.id));
    
    if (select_all) select_all.checked = all_selected;
    if (select_all_bottom) select_all_bottom.checked = all_selected;
}

// 更新购物车汇总
function update_cart_summary() {
    if (!cart_data || !cart_data.items) return;

    let total_price = 0;
    let selected_count = 0;

    cart_data.items.forEach(item => {
        if (selected_items.has(item.id)) {
            total_price += item.price * item.quantity;
            selected_count += item.quantity;
        }
    });

    // 更新选中数量
    const selected_count_el = document.getElementById('selectedCount');
    if (selected_count_el) {
        selected_count_el.textContent = selected_count;
    }

    // 更新总价
    const total_price_el = document.getElementById('totalPrice');
    if (total_price_el) {
        total_price_el.textContent = format_price(total_price);
    }
}

// 修改数量（按钮）
function change_quantity(item_id, delta) {
    const item = cart_data.items.find(i => i.id === item_id);
    if (!item) return;

    const new_quantity = item.quantity + delta;
    
    if (new_quantity < 1) {
        return;
    }
    
    if (item.stock && new_quantity > item.stock) {
        alert('库存不足');
        return;
    }

    update_quantity(item_id, new_quantity);
}

// 更新数量（输入框）
async function update_quantity(item_id, quantity) {
    quantity = parseInt(quantity);
    
    if (isNaN(quantity) || quantity < 1) {
        quantity = 1;
    }

    const item = cart_data.items.find(i => i.id === item_id);
    if (!item) return;

    if (item.stock && quantity > item.stock) {
        alert('库存不足');
        quantity = item.stock;
    }

    try {
        const response = await fetch('/api/cart/item', {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                item_id: item_id,
                quantity: quantity
            })
        });

        if (response.ok) {
            item.quantity = quantity;
            
            // 更新小计
            const cart_item = document.querySelector(`.cart-item[data-id="${item_id}"]`);
            if (cart_item) {
                const subtotal_el = cart_item.querySelector('.col-subtotal');
                const quantity_input = cart_item.querySelector('input[type="number"]');
                
                if (subtotal_el) {
                    subtotal_el.textContent = '¥' + format_price(item.price * item.quantity);
                }
                if (quantity_input) {
                    quantity_input.value = quantity;
                }
            }
            
            update_cart_summary();
        } else {
            alert('更新失败，请稍后重试');
        }
    } catch (error) {
        console.error('更新数量失败:', error);
        alert('更新失败，请稍后重试');
    }
}

// 删除单个商品
async function delete_item(item_id) {
    if (!confirm('确定要删除这个商品吗？')) {
        return;
    }

    try {
        const response = await fetch(`/api/cart/item?item_id=${item_id}`, {
            method: 'DELETE'
        });

        if (response.ok) {
            selected_items.delete(item_id);
            cart_data.items = cart_data.items.filter(item => item.id !== item_id);
            render_cart(cart_data);
            update_cart_summary();
            update_cart_count();
        } else {
            alert('删除失败，请稍后重试');
        }
    } catch (error) {
        console.error('删除商品失败:', error);
        alert('删除失败，请稍后重试');
    }
}

// 删除选中商品
async function delete_selected() {
    if (selected_items.size === 0) {
        alert('请先选择要删除的商品');
        return;
    }

    if (!confirm(`确定要删除选中的 ${selected_items.size} 个商品吗？`)) {
        return;
    }

    try {
        const response = await fetch('/api/cart/items', {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                item_ids: Array.from(selected_items)
            })
        });

        if (response.ok) {
            cart_data.items = cart_data.items.filter(item => !selected_items.has(item.id));
            selected_items.clear();
            render_cart(cart_data);
            update_cart_summary();
            update_cart_count();
        } else {
            alert('删除失败，请稍后重试');
        }
    } catch (error) {
        console.error('删除商品失败:', error);
        alert('删除失败，请稍后重试');
    }
}

// 去结算
function go_to_checkout() {
    if (selected_items.size === 0) {
        alert('请先选择要结算的商品');
        return;
    }

    const item_ids = Array.from(selected_items);
    window.location.href = `/checkout.html?items=${encodeURIComponent(JSON.stringify(item_ids))}`;
}

// 加载结算数据
async function load_checkout_data() {
    show_loading('checkoutItems');
    
    try {
        const url_params = new URLSearchParams(window.location.search);
        const items_param = url_params.get('items');
        const product_id = url_params.get('product_id');
        const quantity = url_params.get('quantity');

        let checkout_data = null;

        if (items_param) {
            // 从购物车结算
            const item_ids = JSON.parse(decodeURIComponent(items_param));
            const response = await fetch('/api/cart/checkout', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ item_ids: item_ids })
            });
            
            if (response.ok) {
                checkout_data = await response.json();
            }
        } else if (product_id) {
            // 立即购买
            const response = await fetch('/api/product/' + product_id);
            if (response.ok) {
                const product = await response.json();
                checkout_data = {
                    items: [{
                        id: product.id,
                        name: product.name,
                        image: product.image,
                        price: product.price,
                        quantity: parseInt(quantity) || 1
                    }]
                };
            }
        }

        if (!checkout_data || !checkout_data.items || checkout_data.items.length === 0) {
            show_error('checkoutItems', '没有可结算的商品');
            return;
        }

        render_checkout_items(checkout_data.items);
        update_checkout_summary(checkout_data);

    } catch (error) {
        console.error('加载结算数据失败:', error);
        show_error('checkoutItems', '加载失败，请稍后重试');
    }
}

// 渲染结算商品列表
function render_checkout_items(items) {
    const container = document.getElementById('checkoutItems');
    if (!container) return;

    container.innerHTML = items.map(item => `
        <div class="checkout-product-item">
            <img src="${item.image || get_placeholder_image(60, 60, item.name)}" 
                 alt="${item.name}"
                 onerror="this.src='${get_placeholder_image(60, 60, item.name)}'">
            <div class="checkout-product-info">
                <div class="checkout-product-name">${item.name}</div>
                <div class="checkout-product-spec">${item.spec || ''}</div>
            </div>
            <div class="checkout-product-quantity">x${item.quantity}</div>
            <div class="checkout-product-price">¥${format_price(item.price * item.quantity)}</div>
        </div>
    `).join('');
}

// 更新结算汇总
function update_checkout_summary(data) {
    let subtotal = 0;
    
    if (data.items) {
        data.items.forEach(item => {
            subtotal += item.price * item.quantity;
        });
    }

    const shipping_fee = subtotal > 0 ? (subtotal >= 99 ? 0 : 10) : 0;
    const discount = 0;
    const final_total = subtotal + shipping_fee - discount;

    document.getElementById('subtotal').textContent = format_price(subtotal);
    document.getElementById('shippingFee').textContent = format_price(shipping_fee);
    document.getElementById('discount').textContent = format_price(discount);
    document.getElementById('finalTotal').textContent = format_price(final_total);
}

// 提交订单
async function submit_order() {
    try {
        const url_params = new URLSearchParams(window.location.search);
        const items_param = url_params.get('items');
        const product_id = url_params.get('product_id');
        const quantity = url_params.get('quantity');

        let order_data = {
            address_id: get_selected_address(),
            payment_method: get_selected_payment(),
            remark: document.getElementById('orderRemark')?.value || ''
        };

        if (items_param) {
            order_data.item_ids = JSON.parse(decodeURIComponent(items_param));
            order_data.type = 'cart';
        } else if (product_id) {
            order_data.product_id = product_id;
            order_data.quantity = parseInt(quantity) || 1;
            order_data.type = 'direct';
        }

        const response = await fetch('/api/orders', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(order_data)
        });

        if (response.ok) {
            const result = await response.json();
            alert('订单提交成功！');
            window.location.href = `/order-detail.html?order_id=${result.order_id}`;
        } else {
            const error_data = await response.json();
            alert(error_data.error || '提交订单失败');
        }
    } catch (error) {
        console.error('提交订单失败:', error);
        alert('提交订单失败，请稍后重试');
    }
}

// 获取选中的地址
function get_selected_address() {
    const selected_radio = document.querySelector('input[name="address"]:checked');
    return selected_radio ? selected_radio.value : null;
}

// 获取选中的支付方式
function get_selected_payment() {
    const selected_radio = document.querySelector('input[name="payment"]:checked');
    return selected_radio ? selected_radio.value : 'alipay';
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

// 导出函数供HTML调用
window.toggle_select_all = toggle_select_all;
window.toggle_item_select = toggle_item_select;
window.delete_selected = delete_selected;
window.change_quantity = change_quantity;
window.update_quantity = update_quantity;
window.delete_item = delete_item;
window.go_to_checkout = go_to_checkout;
window.submit_order = submit_order;
