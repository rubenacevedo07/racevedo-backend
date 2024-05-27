package com.acevedo.security.cart;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class CartService {
    private final CartRepositoryJpa repository;
    private final CartRepository repo;

    @Transactional
    public Number addItem(Cart request) {
        repo.updateTotalWithQuantityForUserAndProduct(request);
        Number counter = repository.countItems(request.getUserEmail());
        return counter;
    }
    @Transactional
    public boolean editItem(CartItem item) {
        var result = repository.editItem(item.getId(),item.getQuantity());
        if(result == 1){
            return true;
        }
        else {
            return false;
        }
    }

    @Transactional
    public boolean deleteItem(CartItem item) {
        repository.deleteById(item.getId());
        return true;
    }

    @Transactional
    public boolean resetCart(String email) {

        int deletedItems = repository.resetCart(email);
        if (deletedItems > 0) {
            System.out.println("Successfully deleted " + deletedItems + " items from cart.");
        } else {
            System.out.println("No items found in the cart for user: " + email);
        }
        return true;
    }

    @Transactional
    public void save(Cart request) {
        var item = Cart.builder()
                .productid(request.getProductid())
                .productname(request.getProductname())
                .photo(request.getPhoto())
                .userid(request.getUserid())
                .quantity(request.getQuantity())
                .subtotal(request.getSubtotal())
                .build();
        repository.save(item);
    }

    public List<Cart> findItems(String userEmail) {
        List<Cart> list = repository.findItems(userEmail);
        return list;
    }

    public Number countItems(String userEmail) {
        Number counter = repository.countItems(userEmail);
        return counter;
    }

}
