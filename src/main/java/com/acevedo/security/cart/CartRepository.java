package com.acevedo.security.cart;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.Transactional;
import org.springframework.stereotype.Repository;

import java.math.BigDecimal;

@Repository
public class CartRepository {
    @PersistenceContext
    private EntityManager entityManager;

    @Transactional
    public Number updateTotalWithQuantityForUserAndProduct(Cart cart) {
        Cart entity = entityManager.createQuery("SELECT e FROM Cart e " +
                                "WHERE e.userEmail = :user AND e.productid = :productid",
                        Cart.class)
                .setParameter("user", cart.getUserEmail())
                .setParameter("productid", cart.getProductid())
                .getResultList()
                .stream()
                .findFirst()
                .orElse(null);

        BigDecimal subtotal = BigDecimal.valueOf(cart.getQuantity() * cart.getPrice());

        if (entity == null) {
            entity = new Cart();
            entity.setUserEmail(cart.getUserEmail());
            entity.setProductid(cart.getProductid());
            entity.setQuantity(cart.getQuantity());
            entity.setPrice(cart.getPrice());
            entity.setProductname(cart.getProductname());
            entity.setSubtotal(subtotal);
            entityManager.persist(entity);
            return cart.getQuantity();
        } else {
            // Update the existing entity
            entity.setQuantity(entity.getQuantity() + cart.getQuantity());
            entity.setSubtotal(subtotal);
            entityManager.merge(entity);
            return entity.getQuantity();
        }
    }
}
