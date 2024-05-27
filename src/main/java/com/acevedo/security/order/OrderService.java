package com.acevedo.security.order;

import com.acevedo.security.cart.Cart;
import com.acevedo.security.cart.CartService;
import com.acevedo.security.order.order_products.OrderProduct;
import com.acevedo.security.order.order_products.OrderProductRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
public class OrderService {
    private final CartService cartService;
    @Autowired
    private OrderRepository orderRepository;
    @Autowired
    private OrderProductRepository orderProductrepository;

    public List<Order> findOrdersItemsByUser(String email) {
        return orderRepository.findOrdersByUserEmail(email);
    }

    @Transactional
    public Order createOrder(String userEmail, CartOrder cartOrder) {
        Order order = new Order();
        order.setUserEmail(userEmail);
        order.setTotal(cartOrder.getTotal());
        order.setOrderDateTime(LocalDateTime.now());
        for (Cart cart : cartOrder.getCart()) {
            OrderProduct orderProduct = new OrderProduct(order, cart);
            order.getOrderProducts().add(orderProduct);
        }
        cartService.resetCart(userEmail);
        return orderRepository.save(order);
    }

}
