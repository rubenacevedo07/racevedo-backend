package com.acevedo.security.cart;

import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface CartRepositoryJpa extends JpaRepository<Cart, Integer> {
    void deleteById(Long id);

    @Modifying
    @Query("DELETE FROM Cart c WHERE c.userEmail = :email")
    public int resetCart(String email);

    @Transactional
    @Modifying
    @Query("UPDATE Cart e SET e.quantity = :quantity WHERE e.id = :itemId")
    public int editItem(@Param("itemId") Integer itemId, @Param("quantity") Integer quantity);

    @Query("select b from Cart b where b.productid=:productID and b.userEmail=:userEmail")
    public List<Cart> findItem(@Param("userEmail") String userEmail, @Param("productID") Integer productID);

    @Query("select b from Cart b where b.userEmail=:userEmail")
    public List<Cart> findItems(@Param("userEmail") String userEmail);

    @Query("SELECT SUM(c.quantity) FROM Cart c WHERE c.userEmail = :userEmail")
    public Number countItems(@Param("userEmail") String userEmail);

    @Query("SELECT b FROM Cart b")
    public List<Cart> getAll();

}
