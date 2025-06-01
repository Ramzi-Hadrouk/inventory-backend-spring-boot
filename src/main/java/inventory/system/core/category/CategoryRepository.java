package inventory.system.core.category;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CategoryRepository extends JpaRepository<Category, Long> {
        boolean existsByNameIgnoreCase(String name);
    Page<Category> findByNameContainingIgnoreCase(String name, Pageable pageable);
}
