package com.acevedo.security.order;

import com.acevedo.security.cart.Cart;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface OrderRepository extends JpaRepository<Order, Long> {
    @Query("SELECT o FROM Order o LEFT JOIN FETCH o.orderProducts op WHERE o.userEmail = :userEmail")
    List<Order> findOrdersByUserEmail(@Param("userEmail") String userEmail);
    @Query("SELECT b FROM Order b WHERE b.userEmail=:userEmail")
    public List<Order> findOrdersByUser(@Param("userEmail")String userEmail);
}
