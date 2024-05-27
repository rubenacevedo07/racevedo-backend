package com.acevedo.security.order.order_products;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface OrderProductRepository extends JpaRepository<OrderProduct, Long> {
    @Query("SELECT p, o FROM Order o, OrderProduct p WHERE o.userEmail = :userEmail")
    List<OrderProduct[]> findOrdersItemsByUser(@Param("userEmail") String userEmail);


}
